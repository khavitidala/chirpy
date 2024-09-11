package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	repo "github.com/khavitidala/chirpy/internal/repositories/chirp"
)

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
}

type userPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginPayload struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		cfg.fileserverHits++
	})
}

func (cfg *apiConfig) metricsResetHandler() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			cfg.fileserverHits = 0
		})
}

func (cfg *apiConfig) metricsConfigHandler() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`
				<html>
					<body>
						<h1>Welcome, Chirpy Admin</h1>
						<p>Chirpy has been visited %d times!</p>
					</body>
				</html>
			`, cfg.fileserverHits)))
		})
}

func respError(errMsg string, statusCode int, w http.ResponseWriter) {
	errVal := struct {
		Error string `json:"error"`
	}{
		Error: errMsg,
	}
	dat, err := json.Marshal(errVal)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"Something went wrong"}`))
		return
	}
	w.WriteHeader(statusCode)
	w.Write(dat)
}

func (cfg *apiConfig) chirpsPOSTHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	type chirpyBody struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	chirp := chirpyBody{}
	err := decoder.Decode(&chirp)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	id := cfg.userAuthentication(r)
	if id == -1 {
		respError("Unauthorize", 401, w)
		return
	}
	newChirp, err := db.CreateChirp(chirp.Body, id)
	if err != nil {
		respError(err.Error(), 400, w)
		return
	}
	dat, err := json.Marshal(newChirp)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	w.WriteHeader(201)
	w.Write(dat)
}

func (cfg *apiConfig) chirpsGETHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	db.Mux.Lock()
	chirps, err := db.GetChirps()
	db.Mux.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		respError(err.Error(), 400, w)
		return
	}
	dat, err := json.Marshal(chirps)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	if id := r.PathValue("chirpID"); id != "" {
		var singleChirp repo.Chirp
		chirpID, err := strconv.Atoi(id)
		if err != nil {
			log.Fatal(err)
			respError("Something went wrong", 500, w)
			return
		}
		for _, val := range chirps {
			if val.Id == chirpID {
				singleChirp = val
				dat, err := json.Marshal(singleChirp)
				if err != nil {
					log.Printf("Error marshalling JSON: %s", err)
					respError("Something went wrong", 500, w)
					return
				}
				w.WriteHeader(200)
				w.Write(dat)
				return
			}
		}
		w.WriteHeader(404)
		return
	}
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) usersPOSTHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	user := userPayload{}
	err := decoder.Decode(&user)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	newUser, err := db.CreateUser(user.Email, user.Password)
	if err != nil {
		respError(err.Error(), 400, w)
		return
	}
	dat, err := json.Marshal(newUser)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	w.WriteHeader(201)
	w.Write(dat)
}

func (cfg *apiConfig) userAuthentication(r *http.Request) (id int) {
	id = -1
	tokenRaw := r.Header.Get("Authorization")
	if tokenRaw == "" {
		return
	}
	tokenSplit := strings.Split(tokenRaw, " ")
	if len(tokenSplit) != 2 {
		return
	}
	token := tokenSplit[1]
	id = cfg.jwtAuthentication(token)
	return
}

func (cfg *apiConfig) jwtAuthentication(token string) (id int) {
	id = -1
	jwtToken, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.jwtSecret), nil
	})
	if err != nil {
		log.Printf("Error decoding JWT token: %s", err)
		return
	}
	if claims, ok := jwtToken.Claims.(*jwt.RegisteredClaims); ok {
		strId, _ := claims.GetSubject()
		id, err = strconv.Atoi(strId)
		if err != nil {
			log.Printf("Error converting ID token: %s", err)
			return
		}
	}
	return
}

func (cfg *apiConfig) tokenAuthentication(db *repo.DB, tokenRaw string) (id int) {
	id = -1
	tokens, err := db.GetTokens()
	if err != nil {
		log.Println(err.Error())
		return
	}
	_, token, err := db.GetTokenByRefreshToken(tokens, tokenRaw)
	if err != nil {
		log.Println(err.Error(), tokenRaw)
		return
	}
	if !token.IsValidToken(tokenRaw) {
		log.Println("invalid token " + tokenRaw)
		return
	}
	id = token.UserId
	return
}

func (cfg *apiConfig) usersPUTHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	user := userPayload{}
	err := decoder.Decode(&user)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	id := cfg.userAuthentication(r)
	if id == -1 {
		respError("Unauthorize", 401, w)
		return
	}
	uptUser, err := db.UpdateUser(user.Email, user.Password, id)
	if err != nil {
		respError(err.Error(), 400, w)
		return
	}
	dat, err := json.Marshal(uptUser)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) loginHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	user := loginPayload{}
	err := decoder.Decode(&user)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	users, err := db.GetUsers()
	if err != nil {
		log.Printf("Error get all users: %s", err)
		respError("Something went wrong", 404, w)
		return
	}
	_, authUser, err := db.GetUserByEmail(users, user.Email)
	if err != nil {
		respError(err.Error(), 401, w)
		return
	}
	userResp, err := db.AuthUserByPassword(user.Password, authUser)
	if err != nil {
		respError(err.Error(), 401, w)
		return
	}
	token, err := cfg.constructJWT(authUser.Id, 1*time.Hour)
	if err != nil {
		respError(err.Error(), 401, w)
		return
	}
	refreshToken, err := db.GetOrCreateRefreshToken(authUser.Id)
	if err != nil {
		respError(err.Error(), 401, w)
		return
	}
	jwtResp := repo.JWTUserResponse{
		Id:           userResp.Id,
		Email:        userResp.Email,
		Token:        token,
		RefreshToken: refreshToken.Token,
	}
	dat, err := json.Marshal(jwtResp)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) refreshTokenHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	tokenRaw := r.Header.Get("Authorization")
	if tokenRaw == "" {
		respError("Unauthorized", 401, w)
		return
	}
	tokenSplit := strings.Split(tokenRaw, " ")
	if len(tokenSplit) != 2 {
		respError("Unauthorized", 401, w)
		return
	}
	token := tokenSplit[1]
	id := cfg.tokenAuthentication(db, token)
	if id == -1 {
		respError("Unauthorized", 401, w)
		return
	}
	jwtToken, err := cfg.constructJWT(id, 1*time.Hour)
	if err != nil {
		respError(err.Error(), 401, w)
		return
	}
	jwtResp := struct {
		Token string `json:"token"`
	}{
		Token: jwtToken,
	}
	dat, err := json.Marshal(jwtResp)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		respError("Something went wrong", 500, w)
		return
	}
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) revokeTokenHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	tokenRaw := r.Header.Get("Authorization")
	if tokenRaw == "" {
		respError("Unauthorized", 401, w)
		return
	}
	tokenSplit := strings.Split(tokenRaw, " ")
	if len(tokenSplit) != 2 {
		respError("Unauthorized", 401, w)
		return
	}
	token := tokenSplit[1]
	id := cfg.tokenAuthentication(db, token)
	if id == -1 {
		respError("Unauthorized", 401, w)
		return
	}
	err := db.RevokeToken(token)
	if err != nil {
		respError(err.Error(), 401, w)
		return
	}
	w.WriteHeader(204)
}

func (cfg *apiConfig) constructJWT(id int, expInDuration time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expInDuration)),
		Subject:   strconv.Itoa(id),
	})
	return token.SignedString([]byte(cfg.jwtSecret))
}

func (cfg *apiConfig) chirpsDELETEHandler(db *repo.DB, w http.ResponseWriter, r *http.Request) {
	id := cfg.userAuthentication(r)
	if id == -1 {
		respError("Unauthorize", 403, w)
		return
	}
	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		respError("Bad Request", 400, w)
		return
	}
	chirpIDcasted, err := strconv.Atoi(chirpID)
	if err != nil {
		log.Println(err)
		respError("Something went wrong", 500, w)
		return
	}
	is_deleted, err := db.DeleteChirp(chirpIDcasted, id)
	if err != nil {
		log.Println(err)
		respError("Something went wrong", 500, w)
		return
	}
	if !is_deleted {
		respError("Unauthorize", 403, w)
		return
	}
	w.WriteHeader(204)
}

func main() {
	godotenv.Load()
	cfg := &apiConfig{fileserverHits: 0, jwtSecret: os.Getenv("JWT_SECRET")}
	db, err := repo.NewDB("database.json")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.Handle("GET /app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.Handle("/admin/metrics", cfg.metricsConfigHandler())
	mux.Handle("/api/reset", cfg.metricsResetHandler())
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) { cfg.chirpsPOSTHandler(db, w, r) })
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) { cfg.chirpsGETHandler(db, w, r) })
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) { cfg.chirpsGETHandler(db, w, r) })
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) { cfg.usersPOSTHandler(db, w, r) })
	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) { cfg.usersPUTHandler(db, w, r) })
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) { cfg.loginHandler(db, w, r) })
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) { cfg.refreshTokenHandler(db, w, r) })
	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) { cfg.revokeTokenHandler(db, w, r) })
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) { cfg.chirpsDELETEHandler(db, w, r) })
	serv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	log.Fatal(serv.ListenAndServe())
}
