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

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type App struct {
	keyService service.KeyManagementService
	caService  ca_service.CaService
	db         *sql.DB
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

	// Initialize PostgreSQL connection
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
	caRepo, err := ca_repository.NewCertificateRepository(db)
	if err != nil {
		panic(err)
	}

	keyService := service.NewKeyManagementService(repo)
	caService := ca_service.NewCaService(caRepo, keyService, caCfg)

	app := &App{keyService: keyService, caService: caService, db: db}

	r := gin.Default()
	r.POST("/keymanagement/generate", func(c *gin.Context) {
		var req struct {
			ID string `json:"id"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		keyPair, err := app.keyService.GenerateKeyPair(req.ID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"id": keyPair.ID})
	})
	r.GET("/keymanagement/:id", func(c *gin.Context) {
		id := c.Param("id")
		keyPair, err := app.keyService.GetKeyPair(id)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"id":        keyPair.ID,
			"publicKey": pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(keyPair.PublicKey)}),
		})
	})
	r.POST("/ca/issue", func(c *gin.Context) {
		var req struct {
			CSR string `json:"csr"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		cert, err := app.caService.IssueCertificate(req.CSR)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"serialNumber": cert.SerialNumber,
			"subject":      cert.Subject,
			"notBefore":    cert.NotBefore,
			"notAfter":     cert.NotAfter,
			"certificate":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		})
	})

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
