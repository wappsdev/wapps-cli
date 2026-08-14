package rotation

import "time"

const testProject = "vaulter-test"

// fixTime, testlerin deterministik "şimdi"sidir — rotasyon kayıtları zaman
// damgası taşır ve gerçek saat kullanmak testleri sallantılı yapardı.
var fixTime = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return fixTime }
