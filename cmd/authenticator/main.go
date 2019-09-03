package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator"
	authnConfig "github.com/cyberark/conjur-authn-k8s-client/pkg/authenticator/config"
	"github.com/cyberark/conjur-authn-k8s-client/pkg/logger"
)

// logging
var errLogger = logger.ErrorLogger
var infoLogger = logger.InfoLogger

func main() {
	var err error

	config, err := authnConfig.NewFromEnv()
	if err != nil {
		printErrorAndExit(logger.CAKC017E)
	}

	// Create new Authenticator
	authn, err := authenticator.New(*config)
	if err != nil {
		printErrorAndExit(logger.CAKC018E)
	}

	// Configure exponential backoff
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 2 * time.Second
	expBackoff.RandomizationFactor = 0.5
	expBackoff.Multiplier = 2
	expBackoff.MaxInterval = 15 * time.Second
	expBackoff.MaxElapsedTime = 2 * time.Minute

	err = backoff.Retry(func() error {
		for {
			infoLogger.Printf(logger.CAKC005I, authn.Config.Username)
			resp, err := authn.Authenticate()
			if err != nil {
				return logger.PrintAndReturnError(logger.CAKC019E)
			}

			err = authn.ParseAuthenticationResponse(resp)
			if err != nil {
				return logger.PrintAndReturnError(logger.CAKC020E)
			}

			if authn.Config.ContainerMode == "init" {
				os.Exit(0)
			}

			// Reset exponential backoff
			expBackoff.Reset()

			infoLogger.Printf(logger.CAKC013I, authn.Config.TokenRefreshTimeout)

			fmt.Println()
			time.Sleep(authn.Config.TokenRefreshTimeout)
		}
	}, expBackoff)

	if err != nil {
		printErrorAndExit(logger.CAKC021E)
	}
}

func printErrorAndExit(errorMessage string) {
	errLogger.Printf(errorMessage)
	os.Exit(1)
}
