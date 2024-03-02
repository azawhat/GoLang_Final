package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name         string
	Email        string
	Password     string
	ConfirmToken string `gorm:"size:100"`
	Confirmed    bool
}

type AdditionalCourses struct {
	ID           uint
	CourseName   string
	Description  string
	Price        float64
	Sessions     int64
	RecordedDate string
	TotalUsers   int64
}

type PageData struct {
	Courses     []AdditionalCourses
	CurrentPage int
	TotalPages  int
	Filter      string
	Sort        string
}

type UserRepository struct {
	DB *gorm.DB
}

var limiter = rate.NewLimiter(1, 3) // Rate limit of 1 request per second with a burst of 3 requests

var logger = logrus.New()

func isSelected(currentSort, optionSort string) bool {
	return currentSort == optionSort
}

func init() {
	// Set log formatter to JSON for structured logging
	logger.SetFormatter(&logrus.JSONFormatter{})
	// Log to stdout
	logger.SetOutput(os.Stdout)
	// Set log level to Info
	logger.SetLevel(logrus.InfoLevel)
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{DB: db}
}

func (ur *UserRepository) CreateUser(user *User) {
	ur.DB.Create(user)
}

func (ur *UserRepository) GetUserByID(id uint) *User {
	var user User
	ur.DB.First(&user, id)
	return &user
}

func (ur *UserRepository) UpdateUserNameByID(id uint, newName string) {
	var user User
	ur.DB.First(&user, id)
	ur.DB.Model(&user).Update("Name", newName)
}

func (ur *UserRepository) DeleteUserByID(id uint) {
	var user User
	ur.DB.Delete(&user, id)
}

func (ur *UserRepository) GetAllUsers() []User {
	var users []User
	ur.DB.Find(&users)
	return users
}

func seq(start, end int) []int {
	s := make([]int, end-start+1)
	for i := range s {
		s[i] = start + i
	}
	return s
}

func main() {
	dsn := "user=golang_database_user password=BULBWrjOPjKObyIy3aZzcEeOzovz5FaW dbname=golang_database sslmode=require port=5432 host=dpg-cnhc65icn0vc73dekkj0-a"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.WithFields(logrus.Fields{
			"action": "database_connection",
			"status": "failure",
		}).Error("Failed to connect to the database")
		os.Exit(1)
	}

	db.AutoMigrate(&User{}, &AdditionalCourses{})

	// Log the migration status
	logger.WithFields(logrus.Fields{
		"action": "database_migration",
		"status": "success",
	}).Info("Database migration completed successfully")

	http.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		confirmHandler(w, r, db)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			// Exceeded request limit
			logger.WithFields(logrus.Fields{
				"action": "rate_limit_exceeded",
				"status": "failure",
			}).Error("Rate limit exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		indexHandler(w, r)
	})

	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		submitHandler(w, r, db)
	})

	http.HandleFunc("/error", errorPageHandler)

	http.HandleFunc("/success", successPageHandler)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginHandler(w, r, db)
	})

	// http.Handle("/additional-courses", AuthMiddleware(http.HandlerFunc(filteredCoursesHandler)))

	http.HandleFunc("/additional-courses", func(w http.ResponseWriter, r *http.Request) {
		filteredCoursesHandler(w, r, db)
	})
	http.HandleFunc("/send-email", func(w http.ResponseWriter, r *http.Request) {
		sendEmailToGmailUsersHandler(w, r, db)
	})
	http.HandleFunc("/update-profile", func(w http.ResponseWriter, r *http.Request) {
		updateProfileHandler(w, r, db)
	})
	http.HandleFunc("/delete-account", func(w http.ResponseWriter, r *http.Request) {
		deleteAccountHandler(w, r, db)
	})

	http.HandleFunc("/manage-courses", manageCoursesHandler)
	http.HandleFunc("/manage-courses/update", func(w http.ResponseWriter, r *http.Request) {
		updateCourseHandler(w, r, db)
	})

	http.HandleFunc("/manage-users/delete", func(w http.ResponseWriter, r *http.Request) {
		deleteUserHandler(w, r, db)
	})

	http.HandleFunc("/manage-courses/delete", func(w http.ResponseWriter, r *http.Request) {
		deleteCourseHandler(w, r, db)
	})

	http.HandleFunc("/manage-courses/add", func(w http.ResponseWriter, r *http.Request) {
		addCourseHandler(w, r, db)
	})

	http.HandleFunc("/manage-users/update", func(w http.ResponseWriter, r *http.Request) {
		updateUserHandler(w, r, db)
	})

	// Serve static files (CSS, JS, images)
	http.Handle("/styles/", http.StripPrefix("/styles/", http.FileServer(http.Dir("styles"))))
	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))
	http.Handle("/page/", http.StripPrefix("/page/", http.FileServer(http.Dir("page"))))
	http.Handle("/javascript/", http.StripPrefix("/javascript/", http.FileServer(http.Dir("javascript"))))
	http.HandleFunc("/manage-users", func(w http.ResponseWriter, r *http.Request) {
		manageUsersHandler(w, r, db)
	})
	logger.WithFields(logrus.Fields{
		"action": "server_start",
		"status": "success",
	}).Info("Server is running on :8080")

	http.ListenAndServe(":8080", nil)
}

func confirmHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	// Extract the token from the query parameters
	token := r.URL.Query().Get("token")

	// Declare a variable to hold the user information
	var user User

	// Find the user with the given confirmation token
	result := db.Where("confirm_token = ?", token).First(&user)

	// Check if the user was found and if the token matches
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// Token not found or invalid
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		} else {
			// Other error (e.g., database connection issue)
			logger.WithFields(logrus.Fields{
				"action": "confirm_token",
				"status": "database_error",
				"error":  result.Error.Error(),
			}).Error("Error in token validation")

			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	user.Confirmed = true

	db.Save(&user)

	http.Redirect(w, r, "/confirmation-success", http.StatusSeeOther)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	isLoggedIn := false
	if cookie, err := r.Cookie("token"); err == nil {
		tokenString := cookie.Value
		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("asdf123"), nil
		})

		if err == nil && token.Valid {
			isLoggedIn = true
		}
	}

	type TemplateData struct {
		LoggedIn   bool
		ProfileURL string
		SignupURL  string
	}

	var data TemplateData

	// Set URLs based on login status
	if isLoggedIn {
		data = TemplateData{
			LoggedIn:   true,
			ProfileURL: "/page/profile.html",
			SignupURL:  "#",
		}
	} else {
		data = TemplateData{
			LoggedIn:   false,
			ProfileURL: "#",
			SignupURL:  "/page/register.html",
		}
	}
	tmpl, err := template.ParseFiles("page/index.html") // adjust the path to your index.html
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func generateToken() (string, error) {
	bytes := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func submitHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method == http.MethodPost {
		name := r.FormValue("name")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if name == "" || email == "" || password == "" {
			logger.WithFields(logrus.Fields{
				"action": "submit_handler",
				"status": "failure",
			}).Error("Invalid form data")
			http.Redirect(w, r, "/error", http.StatusSeeOther)
			return
		}

		nameRegex := regexp.MustCompile(`^[a-zA-Z\s]+$`)
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		passwordRegex := regexp.MustCompile(`^.{8,}$`)

		// Validate name
		if !nameRegex.MatchString(name) {
			http.Error(w, "Invalid name format", http.StatusBadRequest)
			return
		}

		// Validate email
		if !emailRegex.MatchString(email) {
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			return
		}

		// Validate password
		if !passwordRegex.MatchString(password) {
			http.Error(w, "Password must be at least 8 characters long", http.StatusBadRequest)
			return
		}

		token, _ := generateToken()

		userRepo := NewUserRepository(db)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			// handle error
			logger.WithFields(logrus.Fields{
				"action": "password_hashing",
				"status": "failure",
				"error":  err.Error(),
			}).Error("Error hashing password")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		userRepo.CreateUser(&User{Name: name, Email: email, Password: string(hashedPassword), ConfirmToken: token, Confirmed: false})

		err = sendConfirmationEmail(email, token)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"action": "send_confirmation_email",
				"status": "failure",
				"error":  err.Error(),
				"email":  email,
			}).Error("Error sending confirmation email")

			http.Error(w, "There was an error sending the confirmation email. Please try again later.", http.StatusInternalServerError)

			return
		}

		logger.WithFields(logrus.Fields{
			"action": "user_created",
			"status": "success",
			"user":   name,
		}).Info("User created successfully")

		fmt.Printf("Name: %s\nEmail: %s\nPassword: %s\n", name, email, password)

		http.Redirect(w, r, "/success", http.StatusSeeOther)
		return
	}

	logger.WithFields(logrus.Fields{
		"action": "submit_handler",
		"status": "failure",
	}).Error("Method Not Allowed")

	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func errorPageHandler(w http.ResponseWriter, r *http.Request) {
	serveHTMLFile(w, r, "page/error.html")
}

func successPageHandler(w http.ResponseWriter, r *http.Request) {
	serveHTMLFile(w, r, "page/success.html")
}

func serveHTMLFile(w http.ResponseWriter, r *http.Request, filename string) {
	http.ServeFile(w, r, filename)
}

func filteredCoursesHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {

	// userID := r.Context().Value("userID").(uint)

	if r.Method == http.MethodGet {
		action := r.URL.Query().Get("action")
		pageStr := r.URL.Query().Get("page")
		perPage := 6

		var courses []AdditionalCourses
		query := db

		sort := r.URL.Query().Get("sort")
		filter := r.URL.Query().Get("filter")

		if filter != "" {
			query = query.Where("course_name ILIKE ?", "%"+filter+"%") // Adjust this line based on your database column
		}

		if sort == "" {
			query = query.Order("course_name")
		}

		switch action {
		case "filter":
			categories := r.URL.Query()["categories"]
			if len(categories) > 0 {
				query = query.Joins("JOIN course_categories ON additional_courses.id = course_categories.course_id").
					Joins("JOIN categories ON course_categories.category_id = categories.id").
					Where("categories.name IN (?)", categories)
			}
		case "sort":
			// Sorting logic based on the 'sort' parameter
			switch sort {
			case "course_name":
				query = query.Order("course_name")
			case "price":
				query = query.Order("price")
			case "recorded_date":
				query = query.Order("recorded_date")

			default:
				query = query.Order("course_name")
			}
		case "search":
			searchTerm := r.URL.Query().Get("search")
			if searchTerm != "" {
				query = query.Where("course_name LIKE ?", "%"+searchTerm+"%")
			}
		}

		// Get total count for pagination
		var totalCount int64
		query.Model(&AdditionalCourses{}).Count(&totalCount)

		// Calculate offset based on page number
		page, err := strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			page = 1
		}

		offset := (page - 1) * perPage

		query = query.Order(sort).Offset(offset).Limit(perPage).Find(&courses)

		if query.Error != nil {
			logger.WithFields(logrus.Fields{
				"action": "filtered_courses_handler",
				"status": "failure",
				"error":  query.Error.Error(),
			}).Error("Error executing database query")

			// Optionally, you can return an HTTP 500 Internal Server Error status
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Calculate total pages
		totalPages := int(math.Ceil(float64(totalCount) / float64(perPage)))

		// Execute template with pagination data
		err = renderCourses(w, PageData{
			Courses:     courses,
			CurrentPage: page,
			TotalPages:  totalPages,
			Sort:        sort,
			Filter:      filter,
		})

		return
	}

}

func renderCourses(w http.ResponseWriter, pageData PageData) error {
	tmpl, err := template.New("").Funcs(template.FuncMap{"seq": seq}).ParseGlob("page/*.html")
	if err != nil {
		logger.WithFields(logrus.Fields{
			"action": "render_courses",
			"status": "failure",
		}).Error("Error parsing templates: ", err)
		return err
	}

	// Execute template with pagination data
	err = tmpl.ExecuteTemplate(w, "courses.html", pageData)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"action": "render_courses",
			"status": "failure",
		}).Error("Error rendering template: ", err)
	}

	// Log the render courses action
	logger.WithFields(logrus.Fields{
		"action": "render_courses",
		"status": "success",
	}).Info("Courses rendered successfully")

	return err
}

// email confirmation
func sendConfirmationEmail(userEmail, token string) error {
	from := "abylay0505@gmail.com"
	password := "bpte shra ykyk ehxd"

	// SMTP server configuration for Gmail.
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Message.
	message := []byte(
		"To: " + userEmail + "\r\n" +
			"Subject: Confirm your registration\r\n\r\n" +
			"Please click on the link below to confirm your registration:\r\n" +
			"https://golang-final-xe2i.onrender.com/confirm?token=" + token,
	)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{userEmail}, message)
	return err
}

func generateJWT(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("asdf123")) // Replace with a secure key
	return tokenString, err
}

// login
func loginHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Authenticate user
	var user User
	result := db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "User not found", http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if !user.Confirmed {
		http.Error(w, "Please confirm your email to log in", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
		return
	}

	tokenString, err := generateJWT(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: time.Now().Add(72 * time.Hour),
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func ProtectedEndpoint(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value
		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte("asdf123"), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userID := (*claims)["user_id"]
		fmt.Println("Authenticated user ID:", userID)

		next.ServeHTTP(w, r)
	}
}

// Define a handler function for /manage-users route
func manageUsersHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		newName := r.FormValue("newName")

		// Check if email or newName is empty
		if email == "" || newName == "" {
			http.Error(w, "Email or new name cannot be empty", http.StatusBadRequest)
			return
		}

		// Find the user by email
		var user User
		result := db.Where("email = ?", email).First(&user)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				http.Error(w, "User not found", http.StatusNotFound)
			} else {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		// Update the user's name
		user.Name = newName
		db.Save(&user)

		// Redirect to the manage users page or a success page
		http.Redirect(w, r, "/manage-users", http.StatusSeeOther)
		return
	}

	// Render the HTML template for manage users page
	// You can create a template for this page containing the form with email and new name fields
	serveHTMLFile(w, r, "page/manage-users.html")
}

// Add the handler function to the main function
func manageCoursesHandler(w http.ResponseWriter, r *http.Request) {
	// Render manage-courses.html page
	http.ServeFile(w, r, "page/manage-courses.html")
}

func updateCourseHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	// Parse form data
	r.ParseForm()

	// Retrieve course ID from form data
	courseID := r.Form.Get("courseID")

	// Retrieve new course details from form data
	newTitle := r.Form.Get("title")
	newDescription := r.Form.Get("description")
	newPriceStr := r.Form.Get("price")

	// Convert price to float64
	newPrice, err := strconv.ParseFloat(newPriceStr, 64)
	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}

	// Update course details in the database
	var course AdditionalCourses
	result := db.First(&course, courseID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			http.Error(w, "Course not found", http.StatusNotFound)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	course.CourseName = newTitle
	course.Description = newDescription
	course.Price = newPrice

	db.Save(&course)

	// Redirect to manage courses page or respond as appropriate
	http.Redirect(w, r, "/manage-courses", http.StatusSeeOther)
}

func deleteCourseHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	// Parse form data or URL parameters
	r.ParseForm()

	// Retrieve course ID from form data or URL parameters
	courseID := r.Form.Get("courseID")

	// Delete course from the database
	var course AdditionalCourses
	result := db.Delete(&course, courseID)
	if result.Error != nil {
		http.Error(w, "Failed to delete course", http.StatusInternalServerError)
		return
	}

	// Redirect to manage courses page or respond as appropriate
	http.Redirect(w, r, "/manage-courses", http.StatusSeeOther)
}

func addCourseHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	// Parse form data
	r.ParseForm()

	// Retrieve new course details from form data
	newTitle := r.Form.Get("title")
	newDescription := r.Form.Get("description")
	newPriceStr := r.Form.Get("price")

	// Convert price to float64
	newPrice, err := strconv.ParseFloat(newPriceStr, 64)
	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}

	// Create new course record
	newCourse := AdditionalCourses{
		CourseName:  newTitle,
		Description: newDescription,
		Price:       newPrice,
	}

	// Add new course to the database
	db.Create(&newCourse)

	// Redirect to manage courses page or respond as appropriate
	http.Redirect(w, r, "/manage-courses", http.StatusSeeOther)
}

func getAllCourses(db *gorm.DB) []AdditionalCourses {
	var courses []AdditionalCourses
	db.Find(&courses)
	return courses
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authentication check: Ensure the user is logged in
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := cookie.Value
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("asdf123"), nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract user ID from JWT claims
	userID, ok := (*claims)["user_id"].(float64)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusBadRequest)
		return
	}

	// Parse form data
	r.ParseForm()
	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Fetch user from the database
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Update user fields
	user.Name = name
	user.Email = email

	// Hash new password if it's provided
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		user.Password = string(hashedPassword)
	}

	// Save updated user back to the database
	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect or respond as appropriate
	http.Redirect(w, r, "/profile-updated", http.StatusSeeOther)
}

func deleteAccountHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authentication check: Ensure the user is logged in
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := cookie.Value
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("asdf123"), nil // Replace with your JWT secret key
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract user ID from JWT claims
	userID, ok := (*claims)["user_id"].(float64)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusBadRequest)
		return
	}

	// Delete user from the database
	if err := db.Delete(&User{}, uint(userID)).Error; err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	invalidateUserSession(w, r)
	// Redirect to home page or render a goodbye message
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func invalidateUserSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})
}

func updateUserHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Retrieve email and new name from form data
	email := r.Form.Get("email")
	newName := r.Form.Get("newName")

	// Validate form data
	if email == "" || newName == "" {
		http.Error(w, "Email or new name cannot be empty", http.StatusBadRequest)
		return
	}

	// Update user's name in the database
	err = db.Model(&User{}).Where("email = ?", email).Update("name", newName).Error
	if err != nil {
		http.Error(w, "Failed to update user's name", http.StatusInternalServerError)
		return
	}

	// Redirect to the manage users page or respond as appropriate
	http.Redirect(w, r, "/manage-users", http.StatusSeeOther)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Retrieve email from form data
	email := r.Form.Get("email")

	// Validate form data
	if email == "" {
		http.Error(w, "Email cannot be empty", http.StatusBadRequest)
		return
	}

	// Delete user from the database
	if err := db.Where("email = ?", email).Delete(&User{}).Error; err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Redirect to the manage users page or respond as appropriate
	http.Redirect(w, r, "/manage-users", http.StatusSeeOther)
}

func sendEmailToGmailUsersHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	// Fetch all users with Gmail addresses from the database
	var users []User
	result := db.Where("email LIKE ?", "%@gmail.com").Find(&users)
	if result.Error != nil {
		http.Error(w, "Failed to fetch Gmail users", http.StatusInternalServerError)
		return
	}

	// Compose email message
	subject := "Important Message"
	message := "Hello! This is an important message from the admin."

	// Send email to each Gmail user
	for _, user := range users {
		err := sendEmail(user.Email, subject, message)
		if err != nil {
			// Log or handle error
			fmt.Println("Failed to send email to", user.Email)
		}
	}

	// Redirect or respond as appropriate
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func sendEmail(to, subject, message string) error {
	from := "abylay0505@gmail.com"
	password := "bpte shra ykyk ehxd"

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	auth := smtp.PlainAuth("", from, password, smtpHost)

	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		message)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, msg)
	if err != nil {
		fmt.Println("Error sending email:", err)
	}

	return err
}
