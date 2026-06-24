resource "google_storage_bucket_iam_member" "public" {
  bucket = "my-bucket"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
resource "google_sql_database_instance" "db" {
  settings {
    ip_configuration {
      ipv4_enabled = true
    }
  }
}
resource "google_compute_firewall" "open" {
  source_ranges = ["0.0.0.0/0"]
}
