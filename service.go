package svc

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"github.com/go-sql-driver/mysql" // ver >= 1.4
	dbLib "github.com/loc36-core/dbLib" // ver == v0.1
	"github.com/loc36-svc/svc1--svc--lib" // ver == v0.1
	"github.com/nicholoid-dtp/logBook" // ver == v0.1
	"github.com/nicholoid-lib/str" // ver == v0.1
	"github.com/qamarian-dtp/err" // ver == v0.4
	errLib "github.com/qamarian-lib/err" // ver == 0.4
	"github.com/vjeantet/jodaTime" // ver == commit be924ce
	"io/ioutil"
	"net/url"
	"os"
	"time"
)
func init () {
	if initReport == nil {
		return
	}

	errX := dbLib.InitReport ()
	if errX != nil {
		initReport = err.New ("Package 'github.com/loc36-core/dbLib' init failed.", nil, nil, errX)
		return
	}
}

// Function Service () implements the actual service of Loc 36's svc1.
func Service (state int, sensor, pass string) (error) {
	/* ALGORITHM
		step 100: check if sensor exits
		step 110: if an error occurs: handle error
		step 120: if sensor does not exist: return error

		step 130: check if sensor password is correct
		step 140: if an error occurs: handle error
		step 150: if sensor does not exist: return error

		step 160: record state in the database
		step 170: if an error occurs: handle error
	*/

	// step 100
	sensorID := ""
	errX := db.QueryRow (sensorCheck, sensor).Scan (&sensorID)

	// step 110 ..1.. {
	if errX != nil && errX != sql.ErrNoRows {
		errY := err.New ("Unable to confirm sensor's existence.", nil, nil, errX)
		errMssg := fmt.Sprintf ("%s {%s}", errLib.Fup (errY), nameInLogFile)
		logBk.Record ([]byte (errMssg))

		return err.New ("An error occured.", nil, nil)
	}
	// ..1.. }

	// step 120 ..1.. {
	if errX == sql.ErrNoRows {
		return ErrSensorDoesNotExist
	}
	// ..1.. }

	// step 130
	sensorPass := ""
	errZ := db.QueryRow (sensorCheck, sensor, pass).Scan (&sensorPass)
	
	// step 140 ..1.. {
	if errZ != nil && errZ != sql.ErrNoRows {
		errA := err.New ("Unable to confirm password's correctness.", nil, nil, errZ)
		errMssg := fmt.Sprintf ("%s {%s}", errLib.Fup (errA), nameInLogFile)
		logBk.Record ([]byte (errMssg))

		return err.New ("An error occured.", nil, nil)
	}
	// ..1.. }

	// step 150 ..1.. {
	if errZ == sql.ErrNoRows {
		return ErrIncorrectPass
	}
	// ..1.. }

	// step 160 ..1.. {
	// ..2.. {
	recordIDGen := func () (string, error) {
		randStr, errX := str.RandAnStr (4)
		if errX != nil {
			return "", err.New ("Unable to source random part for the ID.", nil, nil, errX)
		}

		timePart := jodaTime.Format ("yyyy-MM-dd-HH-mm-ss-", time.Now ())

		return timePart + randStr, nil
	}
	// ..2.. }

	recordID, errB := recordIDGen ()
	if errB != nil {
		errC := err.New ("Unable to generate ID for the new record.", nil, nil, errB)
		errMssg := fmt.Sprintf ("%s {%s}", errLib.Fup (errC), nameInLogFile)
		logBk.Record ([]byte (errMssg))

		return err.New ("An error occured.", nil, nil)
	}

	conn, errJ := db.Conn (context.Background ())
	if errJ != nil {
		errK := err.New ("Unable to get a connection from the DB, for this service request.", nil, nil, errJ)
		errMssg := fmt.Sprintf ("%s {%s}", errLib.Fup (errK), nameInLogFile)
		logBk.Record ([]byte (errMssg))

		return err.New ("An error occured.", nil, nil)
	}

	errD := dbLib.RecordState (state, recordID, jodaTime.Format ("yyyyMMdd", time.Now ()), jodaTime.Format ("HHmm", time.Now ()), sensor, conn)
	// ..1.. }

	// step 170 ..1.. {
	if errD != nil {
		errE := err.New ("Unable to record state in the DB.", nil, nil, errD)
		errMssg := fmt.Sprintf ("%s {%s}", errLib.Fup (errE), nameInLogFile)
		logBk.Record ([]byte (errMssg))

		return err.New ("An error occured.", nil, nil)
	}
	// ..1.. }

	return nil
}
var (
	db *sql.DB

	sensorCheck = `
		SELECT record_id FROM sensor
		WHERE sensor_id = ?
	`
	passCheck = `
		SELECT record_id FROM sensor
		WHERE sensor_id = ? AND pass = ?
	`

	logBk = logBook.New (os.Stderr)

	ErrSensorDoesNotExist error = err.New ("Sensor does not exist.", nil, nil)
	ErrIncorrectPass error = err.New ("Incorrect sensor password.", nil, nil)

	nameInLogFile string = "svc1--svc.Service ()"
)
func init () {
	if initReport != nil {
		return
	}

	// ..1.. {
	dbmsUser, userPass, connTimeout, writeTimeout, readTimeout, dbmsPubKey, errX := lib.Conf ()
	if errX != nil {
		initReport = err.New ("Unable to fetch service's conf.", nil, nil, errX)
		return
	}
	// ..1.. }

	// ..1.. {
	fileContent, errY := ioutil.ReadFile (dbmsPubKey)
	if errY != nil {
		initReport = err.New ("Unable to read in dbms pub key file.", nil, nil, errY)
		return
	}

	block, _ := pem.Decode (fileContent)
	if block == nil || block.Type != "PUBLIC KEY" {
		initReport = err.New ("DBMS pub key file seems invalid.", nil, nil)
		return
	}

	pubKey, errZ := x509.ParsePKIXPublicKey (block.Bytes)
	if errZ != nil {
		initReport = err.New ("Unable to parse dbms pub key.", nil, nil, errZ)
		return
	}

	key, okA := pubKey.(*rsa.PublicKey)
	if okA == false {
		initReport = err.New ("Result of dbms pub key parsing is not a valid pub key.", nil, nil)
		return
	}

	mysql.RegisterServerPubKey ("dbmsPubKey", key)
	// ..1.. }

	// ..1.. {
	connURLFormat := "%s:%s@tcp(%s:%s)/state?tls=skip-verify&serverPubKey=dbmsPubKey&timeout=%ds&writeTimeout=%ds&" +
		"readTimeout=%ds"

	connURL := fmt.Sprintf (connURLFormat, url.QueryEscape (dbmsUser), url.QueryEscape (userPass),
		url.QueryEscape ("dbms.core.loc36.com"), url.QueryEscape ("50001"), connTimeout, writeTimeout, readTimeout)
	// ..1.. }

	// ..1.. {
	var errB error
	db, errB = sql.Open ("mysql", connURL)
	if errB != nil {
		initReport = err.New ("Unable to connect to the DB.", nil, nil, errB)
		return
	}
	errC := db.Ping ()
	if errC != nil {
		initReport = err.New ("Unable to connect to the DB.", nil, nil, errC)
		return
	}
	// ..1.. }
}
