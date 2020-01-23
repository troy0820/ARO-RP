package main

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/Azure/ARO-RP/pkg/database"
	"github.com/Azure/ARO-RP/pkg/env"
	"github.com/Azure/ARO-RP/pkg/metrics/noop"
	utillog "github.com/Azure/ARO-RP/pkg/util/log"
)

func run(ctx context.Context, log *logrus.Entry) error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: %s resourceid", os.Args[0])
	}

	env, err := env.NewEnv(ctx, log)
	if err != nil {
		return err
	}

	db, err := database.NewDatabase(ctx, log.WithField("component", "database"), env, &noop.Noop{}, "", true)
	if err != nil {
		return err
	}

	doc, err := db.OpenShiftClusters.Get(ctx, strings.ToLower(os.Args[1]))
	if err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(doc)
}

func main() {
	log := utillog.GetLogger()

	if err := run(context.Background(), log); err != nil {
		log.Fatal(err)
	}
}
