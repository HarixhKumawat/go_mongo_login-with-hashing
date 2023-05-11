package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte(os.Getenv("JWT_SECRETKEY"))
	store = sessions.NewCookieStore(key)
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type NewUserData struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	Email    *string `json:"email"`
}
type UpdateCred struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Update   NewUserData
}
type responseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "sessionId")

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "forbidden", http.StatusUnauthorized)
		return
	}

	fmt.Fprintln(w, "The cake is a lie!")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func authenticate(username string, password string, usersCollection *mongo.Collection) bool {
	filter := bson.D{
		{"username", username},
	}

	result := struct {
		ID       primitive.ObjectID `bson:"_id"`
		Username string
		Password string
		Email    string
	}{}

	err := usersCollection.FindOne(context.TODO(), filter).Decode(&result)

	if err != nil {
		return false
	}

	if CheckPasswordHash(password, result.Password) {
		return true
	}
	return false
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	connectionUrl := os.Getenv("MONGO_URI")

	if connectionUrl == "" {
		log.Fatal("You must set your 'MONGODB_URI' environmental variable. See\n\t https://www.mongodb.com/docs/drivers/go/current/usage-examples/#environment-variable")
	}

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(connectionUrl))
	if err != nil {
		panic(err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
			panic(err)
		}
		fmt.Fprintf(w, "server works...")
	})

	usersCollection := client.Database("testing").Collection("users")
	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var newUserData NewUserData
		err := json.NewDecoder(r.Body).Decode(&newUserData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		HashedPassword, err := HashPassword(*newUserData.Password)
		if err != nil {
			http.Error(w, "Something went wrong!!!", http.StatusInternalServerError)
			return
		}

		user := bson.D{{Key: "username", Value: newUserData.Username}, {Key: "password", Value: HashedPassword}, {Key: "email", Value: newUserData.Email}}

		result, err := usersCollection.InsertOne(context.TODO(), user)
		// check for errors in the insertion
		if err != nil {
			panic(err)
		}

		fmt.Fprint(w, result)

	}).Methods("POST")

	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var credentials Credentials
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		authenticated := authenticate(credentials.Username, credentials.Password, usersCollection)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !authenticated {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		session, _ := store.Get(r, "sessionId")
		session.Values["authenticated"] = true
		session.Save(r, w)

		Data := responseData{
			Status:  "ok",
			Message: "login succesful",
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Data)

	}).Methods("POST")

	r.HandleFunc("/secret", secret).Methods("GET")

	r.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "sessionId")
		session.Values["authenticated"] = false
		session.Save(r, w)

		Data := map[string]string{
			"status":  "ok",
			"message": "logout succesful",
		}
		sendData, _ := json.Marshal(Data)

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(sendData))

	}).Methods("POST")

	r.HandleFunc("/updateUser", func(w http.ResponseWriter, r *http.Request) {
		var updateCred UpdateCred
		err := json.NewDecoder(r.Body).Decode(&updateCred)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		authenticated := authenticate(updateCred.Username, updateCred.Password, usersCollection)
		if !authenticated {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		} else {
			filter := bson.D{{Key: "username", Value: updateCred.Username}}
			updateQuery := bson.M{}

			if updateCred.Update.Username != nil {
				updateQuery["$set"] = bson.M{"username": *updateCred.Update.Username}
			}

			if updateCred.Update.Password != nil {
				updateQuery["$set"] = bson.M{"password": *updateCred.Update.Password}
			}

			if updateCred.Update.Email != nil {
				updateQuery["$set"] = bson.M{"email": *updateCred.Update.Email}
			}

			result, err := usersCollection.UpdateOne(context.TODO(), filter, updateQuery)
			if err != nil {
				panic(err)
			}

			Data := map[string]any{
				"status":  "ok",
				"message": "login succesful",
				"data":    result,
			}
			json.NewEncoder(w).Encode(Data)

		}
	}).Methods("POST")

	r.HandleFunc("/addMood", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "new hello world")
	})

	log.Print("SERVER started on port http:/localhost:7000")
	http.ListenAndServe(":7000", r)
}
