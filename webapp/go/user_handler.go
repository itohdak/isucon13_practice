package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultSessionIDKey      = "SESSIONID"
	defaultSessionExpiresKey = "EXPIRES"
	defaultUserIDKey         = "USERID"
	defaultUsernameKey       = "USERNAME"
	bcryptDefaultCost        = bcrypt.MinCost
)

var (
	fallbackImage     = "../img/NoImage.jpg"
	fallbackImagePath = "/home/isucon/webapp/img/NoImage.jpg"
)

var (
	iconCache     = sync.Map{} // (int64, []byte)
	iconHashCache = sync.Map{} // (string, string)
	iconFileCache = sync.Map{} // (int64, string)
	themeCache    = sync.Map{} // (int64, Theme)
	userCache     = sync.Map{} // (int64, User)
)

type UserModel struct {
	ID             int64  `db:"id"`
	Name           string `db:"name"`
	DisplayName    string `db:"display_name"`
	Description    string `db:"description"`
	HashedPassword string `db:"password"`
}

type User struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Theme       Theme  `json:"theme,omitempty"`
	IconHash    string `json:"icon_hash,omitempty"`
}

type Theme struct {
	ID       int64 `json:"id"`
	DarkMode bool  `json:"dark_mode"`
}

type ThemeModel struct {
	ID       int64 `db:"id"`
	UserID   int64 `db:"user_id"`
	DarkMode bool  `db:"dark_mode"`
}

type PostUserRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	// Password is non-hashed password.
	Password string               `json:"password"`
	Theme    PostUserRequestTheme `json:"theme"`
}

type PostUserRequestTheme struct {
	DarkMode bool `json:"dark_mode"`
}

type LoginRequest struct {
	Username string `json:"username"`
	// Password is non-hashed password.
	Password string `json:"password"`
}

type PostIconRequest struct {
	Image []byte `json:"image"`
}

type PostIconResponse struct {
	ID int64 `json:"id"`
}

func getIconHandler(c echo.Context) error {
	ctx := c.Request().Context()

	username := c.Param("username")

	hash := c.Request().Header.Get("If-None-Match")
	if cache, ok := iconHashCache.Load(username); ok {
		if hash == cache.(string) {
			return c.Blob(http.StatusNotModified, "image/jpeg", []byte{})
		}
	}

	tx, err := dbConn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin transaction: "+err.Error())
	}
	defer tx.Rollback()

	var user UserModel
	if err := tx.GetContext(ctx, &user, "SELECT * FROM users WHERE name = ?", username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "not found user that has the given username")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get user: "+err.Error())
	}

	iconFileName, err := getIconFilePathByUserId(ctx, tx, user.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to call getIconFilePathByUserId: "+err.Error())
	}
	c.Response().Header().Set("X-Accel-Redirect", iconFileName)
	return c.NoContent(http.StatusFound)
}

func getFilePathToSaveIcon(image []byte) (string, error) {
	iconHash := sha256.Sum256(image)
	hexHash := hex.EncodeToString(iconHash[:])
	iconFileName := fmt.Sprintf("%s.jpg", hexHash)
	iconFilePath := "/home/isucon/webapp/img/" + iconFileName
	return iconFilePath, nil
}

func saveIcon(image []byte) (string, error) {
	iconFilePath, _ := getFilePathToSaveIcon(image)
	if _, err := os.Stat(iconFilePath); err == nil {
		return iconFilePath, nil
	}
	f, err := os.OpenFile(iconFilePath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0777)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %v", iconFilePath, err)
	}
	defer f.Close()
	if _, err := f.Write(image); err != nil {
		return "", fmt.Errorf("failed to write file %s: %v", iconFilePath, err)
	}
	return iconFilePath, nil
}

func postIconSaveHandler(c echo.Context) error {
	var req *PostIconRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "failed to decode the request body as json")
	}

	_, err := saveIcon(req.Image)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save user icon: "+err.Error())
	}
	return c.NoContent(http.StatusCreated)
}

func postIconHandler(c echo.Context) error {
	ctx := c.Request().Context()

	if err := verifyUserSession(c); err != nil {
		// echo.NewHTTPErrorが返っているのでそのまま出力
		return err
	}

	// error already checked
	sess, _ := session.Get(defaultSessionIDKey, c)
	// existence already checked
	userID := sess.Values[defaultUserIDKey].(int64)

	var req *PostIconRequest
	requestBody := c.Request().Body
	if err := json.NewDecoder(requestBody).Decode(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "failed to decode the request body as json")
	}

	tx, err := dbConn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin transaction: "+err.Error())
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM icons WHERE user_id = ?", userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete old user icon: "+err.Error())
	}

	if resp, err := http.Post("http://s3.maca.jp:8080/api/icon/save", "application/json; charset=UTF-8", requestBody); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to post save icon request to s3: "+err.Error())
	} else {
		defer resp.Body.Close()
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to read response of save icon request: "+err.Error())
		}
	}
	iconFilePath, err := getFilePathToSaveIcon(req.Image)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get icon path: "+err.Error())
	}
	rs, err := tx.ExecContext(ctx, "INSERT INTO icons (user_id, image) VALUES (?, ?)", userID, req.Image)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to insert new user icon: "+err.Error())
	}

	iconID, err := rs.LastInsertId()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get last inserted icon id: "+err.Error())
	}

	var username string
	if err := tx.GetContext(ctx, &username, "SELECT name FROM users WHERE id = ?", userID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to select user name: "+err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to commit: "+err.Error())
	}

	iconCache.Store(userID, req.Image)
	iconHashString := fmt.Sprintf("%x", sha256.Sum256(req.Image))
	iconHashCache.Store(username, iconHashString)
	iconFileCache.Store(userID, iconFilePath)
	userCache.Delete(userID)

	return c.JSON(http.StatusCreated, &PostIconResponse{
		ID: iconID,
	})
}

func getMeHandler(c echo.Context) error {
	ctx := c.Request().Context()

	if err := verifyUserSession(c); err != nil {
		// echo.NewHTTPErrorが返っているのでそのまま出力
		return err
	}

	// error already checked
	sess, _ := session.Get(defaultSessionIDKey, c)
	// existence already checked
	userID := sess.Values[defaultUserIDKey].(int64)

	tx, err := dbConn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin transaction: "+err.Error())
	}
	defer tx.Rollback()

	user, err := getUserById(ctx, tx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return echo.NewHTTPError(http.StatusNotFound, "not found user that has the userid in session")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to call getUserById: "+err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to commit: "+err.Error())
	}

	return c.JSON(http.StatusOK, user)
}

// ユーザ登録API
// POST /api/register
func registerHandler(c echo.Context) error {
	ctx := c.Request().Context()
	defer c.Request().Body.Close()

	req := PostUserRequest{}
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "failed to decode the request body as json")
	}

	if req.Name == "pipe" {
		return echo.NewHTTPError(http.StatusBadRequest, "the username 'pipe' is reserved")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptDefaultCost)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate hashed password: "+err.Error())
	}

	tx, err := dbConn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin transaction: "+err.Error())
	}
	defer tx.Rollback()

	userModel := UserModel{
		Name:           req.Name,
		DisplayName:    req.DisplayName,
		Description:    req.Description,
		HashedPassword: string(hashedPassword),
	}

	result, err := tx.NamedExecContext(ctx, "INSERT INTO users (name, display_name, description, password) VALUES(:name, :display_name, :description, :password)", userModel)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to insert user: "+err.Error())
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get last inserted user id: "+err.Error())
	}

	userModel.ID = userID

	themeModel := ThemeModel{
		UserID:   userID,
		DarkMode: req.Theme.DarkMode,
	}
	rs, err := tx.NamedExecContext(ctx, "INSERT INTO themes (user_id, dark_mode) VALUES(:user_id, :dark_mode)", themeModel)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to insert user theme: "+err.Error())
	}
	themeID, err := rs.LastInsertId()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get last inserted theme id: "+err.Error())
	}
	themeCache.Store(userID, Theme{themeID, req.Theme.DarkMode})

	if out, err := exec.Command("pdnsutil", "add-record", "u.isucon.local", req.Name, "A", "0", powerDNSSubdomainAddress).CombinedOutput(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, string(out)+": "+err.Error())
	}

	user, err := fillUserResponse(ctx, tx, userModel)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fill user: "+err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to commit: "+err.Error())
	}

	return c.JSON(http.StatusCreated, user)
}

// ユーザログインAPI
// POST /api/login
func loginHandler(c echo.Context) error {
	ctx := c.Request().Context()
	defer c.Request().Body.Close()

	req := LoginRequest{}
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "failed to decode the request body as json")
	}

	tx, err := dbConn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin transaction: "+err.Error())
	}
	defer tx.Rollback()

	userModel := UserModel{}
	// usernameはUNIQUEなので、whereで一意に特定できる
	err = tx.GetContext(ctx, &userModel, "SELECT * FROM users WHERE name = ?", req.Username)
	if errors.Is(err, sql.ErrNoRows) {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid username or password")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get user: "+err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to commit: "+err.Error())
	}

	err = bcrypt.CompareHashAndPassword([]byte(userModel.HashedPassword), []byte(req.Password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid username or password")
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to compare hash and password: "+err.Error())
	}

	sessionEndAt := time.Now().Add(1 * time.Hour)

	sessionID := uuid.NewString()

	sess, err := session.Get(defaultSessionIDKey, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to get session")
	}

	sess.Options = &sessions.Options{
		Domain: "u.isucon.local",
		MaxAge: int(60000),
		Path:   "/",
	}
	sess.Values[defaultSessionIDKey] = sessionID
	sess.Values[defaultUserIDKey] = userModel.ID
	sess.Values[defaultUsernameKey] = userModel.Name
	sess.Values[defaultSessionExpiresKey] = sessionEndAt.Unix()

	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session: "+err.Error())
	}

	return c.NoContent(http.StatusOK)
}

// ユーザ詳細API
// GET /api/user/:username
func getUserHandler(c echo.Context) error {
	ctx := c.Request().Context()
	if err := verifyUserSession(c); err != nil {
		// echo.NewHTTPErrorが返っているのでそのまま出力
		return err
	}

	username := c.Param("username")

	tx, err := dbConn.BeginTxx(ctx, nil)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to begin transaction: "+err.Error())
	}
	defer tx.Rollback()

	userModel := UserModel{}
	if err := tx.GetContext(ctx, &userModel, "SELECT * FROM users WHERE name = ?", username); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return echo.NewHTTPError(http.StatusNotFound, "not found user that has the given username")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get user: "+err.Error())
	}

	user, err := fillUserResponse(ctx, tx, userModel)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to fill user: "+err.Error())
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to commit: "+err.Error())
	}

	return c.JSON(http.StatusOK, user)
}

func verifyUserSession(c echo.Context) error {
	sess, err := session.Get(defaultSessionIDKey, c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to get session")
	}

	sessionExpires, ok := sess.Values[defaultSessionExpiresKey]
	if !ok {
		return echo.NewHTTPError(http.StatusForbidden, "failed to get EXPIRES value from session")
	}

	_, ok = sess.Values[defaultUserIDKey].(int64)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "failed to get USERID value from session")
	}

	now := time.Now()
	if now.Unix() > sessionExpires.(int64) {
		return echo.NewHTTPError(http.StatusUnauthorized, "session has expired")
	}

	return nil
}

func getIconFilePathByUserId(ctx context.Context, tx *sqlx.Tx, userID int64) (string, error) {
	if iconFilePath, ok := iconFileCache.Load(userID); ok {
		// iconのファイル名がキャッシュにあれば、それを返す
		return iconFilePath.(string), nil
	}
	var image []byte
	if cache, ok := iconCache.Load(userID); ok {
		// iconの画像がキャッシュにあれば、取得する
		image = cache.([]byte)
	} else {
		// iconの画像もなければ、DBに取りに行く
		if err := tx.GetContext(ctx, &image, "SELECT image FROM icons WHERE user_id = ?", userID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fallbackImagePath, nil
			} else {
				return "", fmt.Errorf("failed to get user icon: %v", err)
			}
		}
		iconCache.Store(userID, image)
	}
	iconFilePath, err := saveIcon(image)
	iconFileCache.Store(userID, iconFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to save icon: %v", err)
	} else {
		return iconFilePath, nil
	}
}

func getUserById(ctx context.Context, tx *sqlx.Tx, userID int64) (User, error) {
	if uCache, ok := userCache.Load(userID); ok {
		return uCache.(User), nil
	} else {
		userModel := UserModel{}
		err := tx.GetContext(ctx, &userModel, "SELECT * FROM users WHERE id = ?", userID)
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, err
		}
		if err != nil {
			return User{}, fmt.Errorf("failed to get user: %v", err)
		}

		user, err := fillUserResponse(ctx, tx, userModel)
		if err != nil {
			return User{}, fmt.Errorf("failed to fill user: %v", err)
		}
		return user, nil
	}
}

/* func getUserByName(userName string) (User, error) {
	return User{}, nil
} */

func fillUserResponse(ctx context.Context, tx *sqlx.Tx, userModel UserModel) (User, error) {
	themeModel := ThemeModel{}
	tCache, ok := themeCache.Load(userModel.ID)
	if ok {
		themeModel = ThemeModel{tCache.(Theme).ID, userModel.ID, tCache.(Theme).DarkMode}
	} else {
		if err := tx.GetContext(ctx, &themeModel, "SELECT * FROM themes WHERE user_id = ?", userModel.ID); err != nil {
			return User{}, err
		}
	}

	var iconHashString string
	hashCache, ok := iconHashCache.Load(userModel.Name)
	if ok {
		iconHashString = hashCache.(string)
	} else {
		var image []byte
		if err := tx.GetContext(ctx, &image, "SELECT image FROM icons WHERE user_id = ?", userModel.ID); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return User{}, err
			}
			image, err = os.ReadFile(fallbackImage)
			if err != nil {
				return User{}, err
			}
		}
		iconCache.Store(userModel.ID, image)
		iconHashString = fmt.Sprintf("%x", sha256.Sum256(image))
		iconHashCache.Store(userModel.Name, iconHashString)
	}

	user := User{
		ID:          userModel.ID,
		Name:        userModel.Name,
		DisplayName: userModel.DisplayName,
		Description: userModel.Description,
		Theme: Theme{
			ID:       themeModel.ID,
			DarkMode: themeModel.DarkMode,
		},
		IconHash: iconHashString,
	}
	userCache.Store(userModel.ID, user)

	return user, nil
}
