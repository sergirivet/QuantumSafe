package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sergirivet/QuantumSafe/internal/discovery"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, databaseURL string) (*Repository, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Repository{pool: pool}, nil
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (repository *Repository) Close() {
	if repository != nil && repository.pool != nil {
		repository.pool.Close()
	}
}

func (repository *Repository) SaveReport(ctx context.Context, report discovery.Report) (ScanRecord, error) {
	if repository == nil || repository.pool == nil {
		return ScanRecord{}, fmt.Errorf("inventory repository is not configured")
	}

	tx, err := repository.pool.Begin(ctx)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("begin inventory transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var scanID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO scans (target, schema_version, scanned_at, duration_ms, addresses_truncated)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		report.Target, report.SchemaVersion, report.ScannedAt, report.DurationMS, report.AddressesTruncated,
	).Scan(&scanID)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("insert scan: %w", err)
	}

	var assetID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO assets (canonical_name)
		VALUES ($1)
		ON CONFLICT (canonical_name) DO UPDATE SET updated_at = now()
		RETURNING id`, report.Target).Scan(&assetID)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("upsert asset: %w", err)
	}

	for _, address := range report.Addresses {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_addresses (scan_id, ip)
			VALUES ($1, $2::inet)
			ON CONFLICT DO NOTHING`, scanID, address.IP); err != nil {
			return ScanRecord{}, fmt.Errorf("insert scan address %q: %w", address.IP, err)
		}
	}

	for _, observed := range report.Services {
		serviceID, err := saveService(ctx, tx, assetID, report.ScannedAt, observed)
		if err != nil {
			return ScanRecord{}, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_services (scan_id, service_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, scanID, serviceID); err != nil {
			return ScanRecord{}, fmt.Errorf("link scan service: %w", err)
		}
		if err := saveTLSObservations(ctx, tx, scanID, serviceID, report.ScannedAt, observed); err != nil {
			return ScanRecord{}, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return ScanRecord{}, fmt.Errorf("commit inventory transaction: %w", err)
	}
	return ScanRecord{ID: scanID}, nil
}

func saveService(ctx context.Context, tx pgx.Tx, assetID int64, observedAt time.Time, observed discovery.Service) (int64, error) {
	var serviceID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO services (asset_id, ip, port, protocol, first_seen_at, last_seen_at)
		VALUES ($1, $2::inet, $3, $4, $5, $5)
		ON CONFLICT (asset_id, ip, port, protocol)
		DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
		RETURNING id`, assetID, observed.IP, observed.Port, observed.Protocol, observedAt).Scan(&serviceID)
	if err != nil {
		return 0, fmt.Errorf("upsert service %s:%d: %w", observed.IP, observed.Port, err)
	}
	return serviceID, nil
}

func saveTLSObservations(ctx context.Context, tx pgx.Tx, scanID, serviceID int64, observedAt time.Time, service discovery.Service) error {
	if service.TLS == nil {
		return nil
	}

	if service.TLS.FingerprintSHA256 != "" {
		certificateID, err := saveCertificate(ctx, tx, *service.TLS)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO service_certificates (scan_id, service_id, certificate_id)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, scanID, serviceID, certificateID); err != nil {
			return fmt.Errorf("link certificate: %w", err)
		}
	}

	evidence, err := json.Marshal(service.TLS)
	if err != nil {
		return fmt.Errorf("marshal TLS evidence: %w", err)
	}
	for _, algorithm := range AlgorithmsFromService(service) {
		var algorithmID int64
		if err := tx.QueryRow(ctx, `
			INSERT INTO algorithms (name, category)
			VALUES ($1, $2)
			ON CONFLICT (name, category) DO UPDATE SET name = EXCLUDED.name
			RETURNING id`, algorithm.Name, algorithm.Category).Scan(&algorithmID); err != nil {
			return fmt.Errorf("upsert algorithm %q: %w", algorithm.Name, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO crypto_usages (scan_id, service_id, algorithm_id, evidence, observed_at)
			VALUES ($1, $2, $3, $4::jsonb, $5)
			ON CONFLICT (scan_id, service_id, algorithm_id) DO NOTHING`, scanID, serviceID, algorithmID, evidence, observedAt); err != nil {
			return fmt.Errorf("insert crypto usage %q: %w", algorithm.Name, err)
		}
	}
	return nil
}

func saveCertificate(ctx context.Context, tx pgx.Tx, observation discovery.TLSObservation) (int64, error) {
	var certificateID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO certificates (fingerprint_sha256, public_key_algorithm, subject, issuer, dns_names, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
			public_key_algorithm = EXCLUDED.public_key_algorithm,
			subject = EXCLUDED.subject,
			issuer = EXCLUDED.issuer,
			dns_names = EXCLUDED.dns_names,
			not_before = EXCLUDED.not_before,
			not_after = EXCLUDED.not_after
		RETURNING id`, observation.FingerprintSHA256, observation.PublicKeyAlgorithm, observation.Subject, observation.Issuer, observation.DNSNames, observation.NotBefore, observation.NotAfter).Scan(&certificateID)
	if err != nil {
		return 0, fmt.Errorf("upsert certificate %q: %w", observation.FingerprintSHA256, err)
	}
	return certificateID, nil
}

func (repository *Repository) GetScan(ctx context.Context, scanID int64) (Snapshot, error) {
	var snapshot Snapshot
	if repository == nil || repository.pool == nil {
		return snapshot, fmt.Errorf("inventory repository is not configured")
	}

	err := repository.pool.QueryRow(ctx, `
		SELECT id, target, schema_version, scanned_at, duration_ms, addresses_truncated
		FROM scans WHERE id = $1`, scanID).Scan(
		&snapshot.ID, &snapshot.Target, &snapshot.SchemaVersion, &snapshot.ScannedAt, &snapshot.DurationMS, &snapshot.AddressesTruncated,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Snapshot{}, fmt.Errorf("%w: scan %d", ErrNotFound, scanID)
		}
		return Snapshot{}, fmt.Errorf("get scan %d: %w", scanID, err)
	}

	addressRows, err := repository.pool.Query(ctx, `SELECT ip::text FROM scan_addresses WHERE scan_id = $1 ORDER BY ip::text`, scanID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("get scan addresses: %w", err)
	}
	for addressRows.Next() {
		var address string
		if err := addressRows.Scan(&address); err != nil {
			addressRows.Close()
			return Snapshot{}, fmt.Errorf("scan address row: %w", err)
		}
		snapshot.Addresses = append(snapshot.Addresses, address)
	}
	addressRows.Close()
	if err := addressRows.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("scan address rows: %w", err)
	}

	err = repository.pool.QueryRow(ctx, `SELECT id, canonical_name FROM assets WHERE canonical_name = $1`, snapshot.Target).Scan(&snapshot.Asset.ID, &snapshot.Asset.Name)
	if err != nil {
		return Snapshot{}, fmt.Errorf("get asset for scan %d: %w", scanID, err)
	}

	serviceRows, err := repository.pool.Query(ctx, `
		SELECT services.id, services.ip::text, services.port, services.protocol
		FROM services
		JOIN scan_services ON scan_services.service_id = services.id
		WHERE scan_services.scan_id = $1
		ORDER BY services.ip::text, services.port`, scanID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("get scan services: %w", err)
	}
	for serviceRows.Next() {
		var service Service
		if err := serviceRows.Scan(&service.ID, &service.IP, &service.Port, &service.Protocol); err != nil {
			serviceRows.Close()
			return Snapshot{}, fmt.Errorf("scan service row: %w", err)
		}
		service.Certificates, err = repository.getCertificates(ctx, scanID, service.ID)
		if err != nil {
			serviceRows.Close()
			return Snapshot{}, err
		}
		service.Algorithms, err = repository.getAlgorithms(ctx, scanID, service.ID)
		if err != nil {
			serviceRows.Close()
			return Snapshot{}, err
		}
		snapshot.Asset.Services = append(snapshot.Asset.Services, service)
	}
	serviceRows.Close()
	if err := serviceRows.Err(); err != nil {
		return Snapshot{}, fmt.Errorf("scan service rows: %w", err)
	}
	return snapshot, nil
}

func (repository *Repository) ListAssets(ctx context.Context, limit, offset int) ([]Asset, int, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT id, canonical_name, COUNT(*) OVER()
		FROM assets
		ORDER BY canonical_name
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	assets := make([]Asset, 0)
	total := 0
	for rows.Next() {
		var asset Asset
		if err := rows.Scan(&asset.ID, &asset.Name, &total); err != nil {
			return nil, 0, fmt.Errorf("asset row: %w", err)
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("asset rows: %w", err)
	}
	return assets, total, nil
}

func (repository *Repository) GetAsset(ctx context.Context, assetID int64) (Asset, error) {
	var asset Asset
	err := repository.pool.QueryRow(ctx, `SELECT id, canonical_name FROM assets WHERE id = $1`, assetID).Scan(&asset.ID, &asset.Name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, fmt.Errorf("%w: asset %d", ErrNotFound, assetID)
		}
		return Asset{}, fmt.Errorf("get asset %d: %w", assetID, err)
	}

	rows, err := repository.pool.Query(ctx, `
		SELECT id, asset_id, ip::text, port, protocol
		FROM services WHERE asset_id = $1
		ORDER BY ip::text, port`, assetID)
	if err != nil {
		return Asset{}, fmt.Errorf("get asset services: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var service Service
		if err := rows.Scan(&service.ID, &service.AssetID, &service.IP, &service.Port, &service.Protocol); err != nil {
			return Asset{}, fmt.Errorf("asset service row: %w", err)
		}
		asset.Services = append(asset.Services, service)
	}
	if err := rows.Err(); err != nil {
		return Asset{}, fmt.Errorf("asset service rows: %w", err)
	}
	return asset, nil
}

func (repository *Repository) ListServices(ctx context.Context, limit, offset int) ([]Service, int, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT services.id, services.asset_id, assets.canonical_name, services.ip::text,
		       services.port, services.protocol, COUNT(*) OVER()
		FROM services
		JOIN assets ON assets.id = services.asset_id
		ORDER BY assets.canonical_name, services.ip::text, services.port
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list services: %w", err)
	}
	defer rows.Close()

	services := make([]Service, 0)
	total := 0
	for rows.Next() {
		var service Service
		if err := rows.Scan(&service.ID, &service.AssetID, &service.AssetName, &service.IP, &service.Port, &service.Protocol, &total); err != nil {
			return nil, 0, fmt.Errorf("service row: %w", err)
		}
		services = append(services, service)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("service rows: %w", err)
	}
	return services, total, nil
}

func (repository *Repository) ListCertificates(ctx context.Context, limit, offset int) ([]Certificate, int, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT id, fingerprint_sha256, public_key_algorithm, subject, issuer, dns_names, not_before, not_after, COUNT(*) OVER()
		FROM certificates
		ORDER BY fingerprint_sha256
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	certificates := make([]Certificate, 0)
	total := 0
	for rows.Next() {
		var certificate Certificate
		if err := rows.Scan(&certificate.ID, &certificate.FingerprintSHA256, &certificate.PublicKeyAlgorithm, &certificate.Subject, &certificate.Issuer, &certificate.DNSNames, &certificate.NotBefore, &certificate.NotAfter, &total); err != nil {
			return nil, 0, fmt.Errorf("certificate row: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("certificate rows: %w", err)
	}
	return certificates, total, nil
}

func (repository *Repository) ListAlgorithms(ctx context.Context, limit, offset int) ([]Algorithm, int, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT id, name, category, COUNT(*) OVER()
		FROM algorithms
		ORDER BY category, name
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list algorithms: %w", err)
	}
	defer rows.Close()

	algorithms := make([]Algorithm, 0)
	total := 0
	for rows.Next() {
		var algorithm Algorithm
		if err := rows.Scan(&algorithm.ID, &algorithm.Name, &algorithm.Category, &total); err != nil {
			return nil, 0, fmt.Errorf("algorithm row: %w", err)
		}
		algorithms = append(algorithms, algorithm)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("algorithm rows: %w", err)
	}
	return algorithms, total, nil
}

func (repository *Repository) getCertificates(ctx context.Context, scanID, serviceID int64) ([]Certificate, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT certificates.fingerprint_sha256, certificates.public_key_algorithm, certificates.subject, certificates.issuer,
		       certificates.dns_names, certificates.not_before, certificates.not_after
		FROM certificates
		JOIN service_certificates ON service_certificates.certificate_id = certificates.id
		WHERE service_certificates.scan_id = $1 AND service_certificates.service_id = $2
		ORDER BY certificates.fingerprint_sha256`, scanID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("get certificates: %w", err)
	}
	defer rows.Close()

	certificates := make([]Certificate, 0)
	for rows.Next() {
		var certificate Certificate
		if err := rows.Scan(&certificate.FingerprintSHA256, &certificate.PublicKeyAlgorithm, &certificate.Subject, &certificate.Issuer, &certificate.DNSNames, &certificate.NotBefore, &certificate.NotAfter); err != nil {
			return nil, fmt.Errorf("certificate row: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("certificate rows: %w", err)
	}
	return certificates, nil
}

func (repository *Repository) getAlgorithms(ctx context.Context, scanID, serviceID int64) ([]Algorithm, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT algorithms.name, algorithms.category
		FROM algorithms
		JOIN crypto_usages ON crypto_usages.algorithm_id = algorithms.id
		WHERE crypto_usages.scan_id = $1 AND crypto_usages.service_id = $2
		ORDER BY algorithms.category, algorithms.name`, scanID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("get algorithms: %w", err)
	}
	defer rows.Close()

	algorithms := make([]Algorithm, 0)
	for rows.Next() {
		var algorithm Algorithm
		if err := rows.Scan(&algorithm.Name, &algorithm.Category); err != nil {
			return nil, fmt.Errorf("algorithm row: %w", err)
		}
		algorithms = append(algorithms, algorithm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("algorithm rows: %w", err)
	}
	return algorithms, nil
}
