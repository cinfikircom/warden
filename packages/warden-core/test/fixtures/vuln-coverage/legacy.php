<?php
// Kapsam-genişletme fixture'ı (PHP) — bilerek açıklı. Üretimde KULLANMA.
function loadSession() {
    // PHP object injection
    $obj = unserialize($_GET['data']);
    return $obj;
}
