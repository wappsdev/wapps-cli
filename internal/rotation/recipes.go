package rotation

import (
	"context"
	"fmt"
)

// v1 recipe tipleri (SPEC §8.6.1/§10.4 — pinlenmiş küme).
const (
	RecipeDBRolePhase1   = "db-role/phase1"
	RecipeCoolifyStart   = "coolify-env/start"
	RecipeCFManual       = "cf-manual"
	RecipeProviderManual = "provider-manual"
	RecipeWorkerSecret   = "worker-secret"
)

// DefaultRecipes, v1 recipe kümesini ad→Recipe olarak döner. Motor worklist
// girdisinin `recipe` alanıyla buradan çözer.
func DefaultRecipes() map[string]Recipe {
	return map[string]Recipe{
		RecipeDBRolePhase1:   dbRolePhase1{},
		RecipeCoolifyStart:   coolifyStart{},
		RecipeCFManual:       manualRecipe{typ: RecipeCFManual, dashboard: "Cloudflare"},
		RecipeProviderManual: manualRecipe{typ: RecipeProviderManual, dashboard: "provider"},
		RecipeWorkerSecret:   workerSecret{},
	}
}

// --- db-role/phase1 ---------------------------------------------------------

// dbRolePhase1, Postgres rol parolası rotasyonudur (§10.4): taze parola bas →
// (motor store'a yazar) → vaulter-db-admin job ile ALTER ROLE (DESUPER_PHASE=phase1
// + gateway-last onurlandırılır) → tüketici env push + /start → prod smoke doğrula.
type dbRolePhase1 struct{}

func (dbRolePhase1) Type() string { return RecipeDBRolePhase1 }
func (dbRolePhase1) Manual() bool { return false }

func (dbRolePhase1) Rotate(ctx context.Context, req Request) ([]byte, error) {
	// Taze parola Executor'dan (canlı: vaulter-db-admin; mock: deterministik).
	return req.Exec.MintSecret(ctx, "db-password", req.Params)
}

func (dbRolePhase1) Apply(ctx context.Context, req Request, newVal []byte) error {
	// (1) ALTER ROLE — DESUPER_PHASE=phase1 semantiği + gateway-last SIRASI
	// Executor'a params ile taşınır (ordering_constraints motorda uygulanır).
	if err := req.Exec.AlterDBRole(ctx, req.Params, newVal); err != nil {
		return fmt.Errorf("rotation.db-role/phase1: alter role: %w", err)
	}
	// (2) Tüketici env push (base64 PATCH) — DB URL'i taşıyan app(ler).
	if err := req.Exec.PushCoolifyEnv(ctx, req.Params, newVal); err != nil {
		return fmt.Errorf("rotation.db-role/phase1: push env: %w", err)
	}
	// (3) ZORUNLU /start — env değişikliği restart olmadan etki etmez.
	if err := req.Exec.RestartCoolifyApp(ctx, req.Params); err != nil {
		return fmt.Errorf("rotation.db-role/phase1: restart: %w", err)
	}
	return nil
}

func (dbRolePhase1) Verify(ctx context.Context, req Request, _ []byte) error {
	probe := req.Params["verify"]
	if probe == "" {
		probe = "deploy-verification" // §10.4.3 prod smoke
	}
	return req.Exec.Probe(ctx, probe, req.Params)
}

func (dbRolePhase1) Instructions(Request) string { return "" }

// --- coolify-env/start ------------------------------------------------------

// coolifyStart, Coolify app env'i olarak tutulan bir değerin rotasyonudur (§10.4):
// yeni değer store'a → Coolify env PATCH (base64) → app RESTART (env değişikliği
// /start olmadan etki etmez, Coolify v4) → doğrula.
type coolifyStart struct{}

func (coolifyStart) Type() string { return RecipeCoolifyStart }
func (coolifyStart) Manual() bool { return false }

func (coolifyStart) Rotate(ctx context.Context, req Request) ([]byte, error) {
	return req.Exec.MintSecret(ctx, "token", req.Params)
}

func (coolifyStart) Apply(ctx context.Context, req Request, newVal []byte) error {
	if err := req.Exec.PushCoolifyEnv(ctx, req.Params, newVal); err != nil {
		return fmt.Errorf("rotation.coolify-env/start: push env: %w", err)
	}
	// MECBURİ /start — aksi halde env değişikliği ölü (Coolify v4).
	if err := req.Exec.RestartCoolifyApp(ctx, req.Params); err != nil {
		return fmt.Errorf("rotation.coolify-env/start: restart: %w", err)
	}
	return nil
}

func (coolifyStart) Verify(ctx context.Context, req Request, _ []byte) error {
	probe := req.Params["verify"]
	if probe == "" {
		probe = "http-200"
	}
	return req.Exec.Probe(ctx, probe, req.Params)
}

func (coolifyStart) Instructions(Request) string { return "" }

// --- worker-secret (dual-kid) ----------------------------------------------

// workerSecret, CF Worker secret'ı rotasyonudur (§9): taze secret bas → (store) →
// tüketicinin desteklediği yerde dual-`kid` ile SetWorkerSecret (yeni kid eklenir,
// eski hâlâ geçerliyken) → doğrula. Admin makineden bundle-scoped deploy token'la.
type workerSecret struct{}

func (workerSecret) Type() string { return RecipeWorkerSecret }
func (workerSecret) Manual() bool { return false }

func (workerSecret) Rotate(ctx context.Context, req Request) ([]byte, error) {
	return req.Exec.MintSecret(ctx, "worker-secret", req.Params)
}

func (workerSecret) Apply(ctx context.Context, req Request, newVal []byte) error {
	kid := req.Params["kid"]
	if kid == "" {
		kid = "next" // dual-kid: yeni kid, eski kid geçerli kalır
	}
	if err := req.Exec.SetWorkerSecret(ctx, req.Params, newVal, kid); err != nil {
		return fmt.Errorf("rotation.worker-secret: set (kid=%s): %w", kid, err)
	}
	return nil
}

func (workerSecret) Verify(ctx context.Context, req Request, _ []byte) error {
	probe := req.Params["verify"]
	if probe == "" {
		probe = "worker-liveness"
	}
	return req.Exec.Probe(ctx, probe, req.Params)
}

func (workerSecret) Instructions(Request) string { return "" }

// --- cf-manual / provider-manual (insan-onaylı) -----------------------------

// manualRecipe, tam otomatikleştirilemeyen (dashboard/API el adımları gereken)
// değerlerin recipe'idir (§8.6.1: cf-manual, provider-manual). PRECISE bir insan
// checklist'i üretir, onay token'ı ZORUNLU kılar ve HİÇBİR otomatik yürütme yapmaz.
type manualRecipe struct {
	typ       string
	dashboard string
}

func (m manualRecipe) Type() string { return m.typ }
func (m manualRecipe) Manual() bool { return true }

func (m manualRecipe) Rotate(_ context.Context, _ Request) ([]byte, error) {
	// Manuel recipe değeri dashboard'da üretilir; motor store'a yeni değeri
	// insan-onayı SONRASI yazar. Placeholder değer üretilmez — Apply onayı zorlar.
	return nil, nil
}

func (m manualRecipe) Apply(_ context.Context, req Request, _ []byte) error {
	// İnsan-attestasyonu ZORUNLU: onay token'ı yoksa DURAKLA (§8.6.4). Otomatik
	// yürütme YOK; motor bu girdiyi CONSUMER_UPDATED'e ilerletmez.
	if req.Confirm == "" {
		return ErrConfirmationRequired
	}
	return nil
}

func (m manualRecipe) Verify(ctx context.Context, req Request, _ []byte) error {
	probe := req.Params["verify"]
	if probe == "" {
		return nil // manuel doğrulama insan checklist'inde
	}
	return req.Exec.Probe(ctx, probe, req.Params)
}

func (m manualRecipe) Instructions(req Request) string {
	url := req.Params["dashboard_url"]
	if url == "" {
		url = "(dashboard URL in recipe_params.dashboard_url)"
	}
	return fmt.Sprintf(
		"MANUAL rotation (%s) — key %q in project %q:\n"+
			"  1. Rotate the credential in the %s dashboard: %s\n"+
			"  2. Store the NEW value: wapps secrets set %s\n"+
			"  3. Verify: %s\n"+
			"  4. Confirm completion in a TTY (agent mode is refused — human attestation).",
		m.dashboard, req.Key, req.Project, m.dashboard, url, req.Key, req.Params["verify"],
	)
}
