package main

import (
	caconfig "core-ca/ca/config"
	ca_repository "core-ca/ca/repository"
	ca_service "core-ca/ca/service"
	"os"
	"os/signal"
	"syscall"

	keyconfig "core-ca/keymanagement/config"
	"core-ca/keymanagement/repository"
	"core-ca/keymanagement/service"
	"crypto/x509"
	"database/sql"
	"encoding/pem"

	_ "core-ca/docs"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"net/http"
)

// @title Core CA API
// @version 1.0
// @description Certificate Authority API for key management and certificate operations
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /

// KeyGenerateRequest represents the request for key generation
type KeyGenerateRequest struct {
	ID string `json:"id" binding:"required" example:"my-key-id"`
}

// KeyGenerateResponse represents the response for key generation
type KeyGenerateResponse struct {
	ID string `json:"id" example:"my-key-id"`
}

// KeyGetResponse represents the response for getting a key
type KeyGetResponse struct {
	ID        string `json:"id" example:"my-key-id"`
	PublicKey string `json:"publicKey" example:"-----BEGIN RSA PUBLIC KEY-----\n..."`
}

// CertificateIssueRequest represents the request for issuing a certificate
type CertificateIssueRequest struct {
	CSR string `json:"csr" binding:"required" example:"-----BEGIN CERTIFICATE REQUEST-----..."`
}

// CertificateRevokeRequest represents the request for revoking a certificate
type CertificateRevokeRequest struct {
	SerialNumber string `json:"serial_number" binding:"required" example:"123456789"`
	Reason       string `json:"reason" binding:"required" example:"compromised"`
}

// CertificateRevokeResponse represents the response for certificate revocation
type CertificateRevokeResponse struct {
	Message string `json:"message" example:"Certificate revoked"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid request"`
}

type App struct {
	keyService service.KeyManagementService
	caService  ca_service.CaService
	db         *sql.DB
}

// @Summary Generate a new key pair
// @Description Generate a new RSA key pair with the specified ID
// @Tags Key Management
// @Accept json
// @Produce json
// @Param request body KeyGenerateRequest true "Key generation request"
// @Success 200 {object} KeyGenerateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /keymanagement/generate [post]
func (app *App) GenerateKeyPair(c *gin.Context) {
	var req KeyGenerateRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		return
	}

	keyPair, err := app.keyService.GenerateKeyPair(req.ID)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(200, KeyGenerateResponse{ID: keyPair.ID})
}

// @Summary Get a key pair by ID
// @Description Retrieve a key pair by its ID and return the public key
// @Tags Key Management
// @Accept json
// @Produce json
// @Param id path string true "Key ID"
// @Success 200 {object} KeyGetResponse
// @Failure 500 {object} ErrorResponse
// @Router /keymanagement/{id} [get]
func (app *App) GetKeyPair(c *gin.Context) {
	id := c.Param("id")
	keyPair, err := app.keyService.GetKeyPair(id)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(200, KeyGetResponse{
		ID:        keyPair.ID,
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(keyPair.PublicKey)})),
	})
}

// @Summary Issue a new certificate
// @Description Issue a new certificate from a Certificate Signing Request (CSR)
// @Tags Certificate Authority
// @Accept json
// @Produce application/x-pem-file
// @Param request body CertificateIssueRequest true "Certificate issuance request"
// @Success 200 {string} string "PEM encoded certificate"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/issue [post]
func (app *App) IssueCertificate(c *gin.Context) {
	var req CertificateIssueRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		return
	}
	certPEM, err := app.caService.IssueCertificate(req.CSR)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/x-pem-file", certPEM)
}

// @Summary Revoke a certificate
// @Description Revoke a certificate by its serial number with a specified reason
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param request body CertificateRevokeRequest true "Certificate revocation request"
// @Success 200 {object} CertificateRevokeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/revoke [post]
func (app *App) RevokeCertificate(c *gin.Context) {
	var req CertificateRevokeRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	err := app.caService.RevokeCertificate(req.SerialNumber, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, CertificateRevokeResponse{Message: "Certificate revoked"})
}

// @Summary Get Certificate Revocation List (CRL)
// @Description Retrieve the current Certificate Revocation List
// @Tags Certificate Authority
// @Accept json
// @Produce application/x-pem-file
// @Success 200 {string} string "PEM encoded CRL"
// @Failure 500 {object} ErrorResponse
// @Router /ca/crl [get]
func (app *App) GetCRL(c *gin.Context) {
	crlPEM, err := app.caService.GetCRL()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/x-pem-file", crlPEM)
}

func main() {
	keyCfg, err := keyconfig.LoadConfig()
	if err != nil {
		panic(err)
	}

	caCfg, err := caconfig.LoadConfig()
	if err != nil {
		panic(err)
	}

	// Initialize PostgreSQL connection.
	db, err := sql.Open("pgx", caCfg.Database.DSN)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		panic("failed to ping database: " + err.Error())
	}

	repo, err := repository.NewSoftHsmKeyPairRepository(keyCfg.SoftHSMModule, keyCfg.SoftHSMSlot, keyCfg.SoftHSMPin)
	if err != nil {
		panic(err)
	}
	caRepo, err := ca_repository.NewRepository(db)
	if err != nil {
		panic(err)
	}

	keyService := service.NewKeyManagementService(repo)
	caService := ca_service.NewCaService(caRepo, keyService, caCfg)

	app := &App{keyService: keyService, caService: caService, db: db}

	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)

	// Swagger endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.POST("/keymanagement/generate", app.GenerateKeyPair)
	r.GET("/keymanagement/:id", app.GetKeyPair)
	r.POST("/ca/issue", app.IssueCertificate)
	r.POST("/ca/revoke", app.RevokeCertificate)
	r.GET("/ca/crl", app.GetCRL)

	go func() {
		if err := r.Run(":8080"); err != nil {
			panic(err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	repo.Finalize()
}
