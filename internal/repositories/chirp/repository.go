package chirp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	path string
	Mux  *sync.RWMutex
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password []byte `json:"password"`
}

type Token struct {
	Id       int    `json:"id"`
	UserId   int    `json:"user_id"`
	Token    string `json:"token"`
	ExpireAt int64  `json:"expire_at"`
}

type AuthUserResponse struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type JWTUserResponse struct {
	Id           int    `json:"id"`
	Email        string `json:"email"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
	Tokens map[int]Token `json:"token"`
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		Mux:  &sync.RWMutex{},
	}
	err := db.ensureDB()
	if err != nil {
		return db, err
	}
	return db, nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, authorId int) (newChirp Chirp, err error) {
	chirpBody, err := db.validateBody(body)
	if err != nil {
		return Chirp{}, err
	}
	db.Mux.Lock()
	defer db.Mux.Unlock()
	chirps, err := db.GetChirps()
	if err != nil {
		return Chirp{}, err
	}
	lenChirps := len(chirps)
	if lenChirps == 0 {
		newChirp = Chirp{
			Id:       1,
			Body:     chirpBody,
			AuthorId: authorId,
		}
	} else {
		newChirp = Chirp{
			Id:       chirps[lenChirps-1].Id + 1,
			Body:     chirpBody,
			AuthorId: authorId,
		}
	}
	chirps = append(chirps, newChirp)
	dbs, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	for _, chi := range chirps {
		dbs.Chirps[chi.Id] = chi
	}
	err = db.writeDB(dbs)
	if err != nil {
		return Chirp{}, err
	}
	return newChirp, nil
}

func (db *DB) DeleteChirp(chirpID int, authorId int) (bool, error) {
	db.Mux.Lock()
	defer db.Mux.Unlock()
	dbs, err := db.loadDB()
	if err != nil {
		return false, err
	}
	is_deleted := false
	for _, chi := range dbs.Chirps {
		if chi.Id == chirpID && chi.AuthorId == authorId {
			delete(dbs.Chirps, chi.Id)
			is_deleted = true
		}
	}
	err = db.writeDB(dbs)
	if err != nil {
		return false, err
	}
	return is_deleted, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	dbs, err := db.loadDB()
	if err != nil {
		return []Chirp{}, err
	}
	chirps := []Chirp{}
	for _, chi := range dbs.Chirps {
		chirps = append(chirps, chi)
	}
	if len(chirps) > 0 {
		sort.Slice(chirps, func(i, j int) bool { return chirps[i].Id < chirps[j].Id })
	}
	return chirps, nil
}

func (db *DB) CreateUser(email string, password string) (newUserResponse AuthUserResponse, err error) {
	db.Mux.Lock()
	defer db.Mux.Unlock()
	users, err := db.GetUsers()
	if err != nil {
		return
	}
	lenUsers := len(users)
	pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	var newUser User
	if lenUsers == 0 {
		newUser = User{
			Id:       1,
			Email:    email,
			Password: pass,
		}
	} else {
		if err = db.ValidateUniqueUser(users, email); err != nil {
			return
		}
		newUser = User{
			Id:       users[lenUsers-1].Id + 1,
			Email:    email,
			Password: pass,
		}
	}
	users = append(users, newUser)
	dbs, err := db.loadDB()
	if err != nil {
		return
	}
	for _, user := range users {
		dbs.Users[user.Id] = user
	}
	err = db.writeDB(dbs)
	if err != nil {
		return
	}
	newUserResponse = AuthUserResponse{
		Id:    newUser.Id,
		Email: newUser.Email,
	}
	return
}

func (db *DB) UpdateUser(email string, password string, id int) (uptUserResponse AuthUserResponse, err error) {
	db.Mux.Lock()
	defer db.Mux.Unlock()
	pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	dbs, err := db.loadDB()
	if err != nil {
		return
	}
	if _, ok := dbs.Users[id]; !ok {
		err = errors.New("user not found")
		return
	}
	dbs.Users[id] = User{
		Id:       id,
		Email:    email,
		Password: pass,
	}
	err = db.writeDB(dbs)
	if err != nil {
		return
	}
	uptUserResponse = AuthUserResponse{
		Id:    dbs.Users[id].Id,
		Email: dbs.Users[id].Email,
	}
	return
}

func (db *DB) ValidateUniqueUser(users []User, email string) error {
	for _, user := range users {
		if user.Email == email {
			return errors.New("email already exists")
		}
	}
	return nil
}

func (db *DB) GetUserByEmail(users []User, email string) (int, User, error) {
	for idx, user := range users {
		if user.Email == email {
			return idx, user, nil
		}
	}
	return -1, User{}, errors.New("user not found")
}

func (db *DB) AuthUserByPassword(plainPassword string, user User) (AuthUserResponse, error) {
	return AuthUserResponse{
		Id:    user.Id,
		Email: user.Email,
	}, bcrypt.CompareHashAndPassword(user.Password, []byte(plainPassword))
}

func (db *DB) GetUsers() (users []User, err error) {
	dbs, err := db.loadDB()
	if err != nil {
		return
	}
	for _, user := range dbs.Users {
		users = append(users, user)
	}
	if len(users) > 0 {
		sort.Slice(users, func(i, j int) bool { return users[i].Id < users[j].Id })
	}
	return
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	f, err := os.Open(db.path)
	if os.IsNotExist(err) {
		err = db.writeDB(
			DBStructure{
				Chirps: map[int]Chirp{},
				Users:  map[int]User{},
				Tokens: map[int]Token{},
			},
		)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	dbs := DBStructure{}
	dat, err := os.ReadFile(db.path)
	if err != nil {
		return dbs, err
	}
	err = json.Unmarshal(dat, &dbs)
	if err != nil {
		return dbs, err
	}
	return dbs, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	dat, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}
	err = os.WriteFile(db.path, dat, 0666)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) validateBody(body string) (string, error) {
	if len(body) > 140 {
		return body, errors.New("Chirp is too long")
	}
	var isMask bool
	gatherStr := []string{}
	maskWord := [3]string{"kerfuffle", "sharbert", "fornax"}
	for _, s := range strings.Split(body, " ") {
		isMask = false
		for _, m := range maskWord {
			if strings.ToLower(s) == m {
				isMask = true
				break
			}
		}
		if isMask {
			gatherStr = append(gatherStr, "****")
			continue
		}
		gatherStr = append(gatherStr, s)
	}
	return strings.Join(gatherStr, " "), nil
}

func (token *Token) IsTokenExpire() bool {
	return time.Now().Unix() > token.ExpireAt
}

func (token *Token) generateToken() (newToken string, err error) {
	c := 32
	b := make([]byte, c)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	newToken = hex.EncodeToString(b)
	return
}

func (token *Token) IsValidToken(inputToken string) bool {
	if token.IsTokenExpire() {
		return false
	}
	return inputToken == token.Token
}

func (db *DB) GetTokens() (tokens []Token, err error) {
	dbs, err := db.loadDB()
	if err != nil {
		return
	}
	for _, user := range dbs.Tokens {
		tokens = append(tokens, user)
	}
	if len(tokens) > 0 {
		sort.Slice(tokens, func(i, j int) bool { return tokens[i].ExpireAt > tokens[j].ExpireAt })
	}
	return
}

func (db *DB) GetTokenByUserId(tokens []Token, userId int) (int, Token, error) {
	for idx, token := range tokens {
		if token.UserId == userId {
			return idx, token, nil
		}
	}
	return -1, Token{}, errors.New("token not found")
}

func (db *DB) GetTokenByRefreshToken(tokens []Token, refreshToken string) (int, Token, error) {
	for idx, token := range tokens {
		if token.Token == refreshToken {
			return idx, token, nil
		}
	}
	return -1, Token{}, errors.New("token not found")
}

func (db *DB) createToken(userId int, tokens []Token) (token Token, err error) {
	db.Mux.Lock()
	defer db.Mux.Unlock()
	maxTokenId := 1
	for _, t := range tokens {
		if t.Id > maxTokenId {
			maxTokenId = t.Id
		}
	}
	token = Token{
		Id:       maxTokenId,
		UserId:   userId,
		ExpireAt: time.Now().AddDate(0, 0, 60).Unix(),
	}
	token.Token, err = token.generateToken()
	if err != nil {
		return
	}
	dbs, err := db.loadDB()
	if err != nil {
		return
	}
	dbs.Tokens[token.Id] = token
	err = db.writeDB(dbs)
	if err != nil {
		return
	}
	return
}

func (db *DB) RevokeToken(refreshToken string) (err error) {
	db.Mux.Lock()
	defer db.Mux.Unlock()
	dbs, err := db.loadDB()
	if err != nil {
		return
	}
	for _, tk := range dbs.Tokens {
		if tk.Token == refreshToken {
			delete(dbs.Tokens, tk.Id)
		}
	}
	err = db.writeDB(dbs)
	if err != nil {
		return
	}
	return
}

func (db *DB) GetOrCreateRefreshToken(userId int) (token Token, err error) {
	tokens, err := db.GetTokens()
	if err != nil {
		return
	}
	id, token, _ := db.GetTokenByUserId(tokens, userId)
	if id == -1 {
		token, err = db.createToken(userId, tokens)
	}
	return
}
