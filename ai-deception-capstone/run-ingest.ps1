# Run the ingestion simulator to refresh processed_threat_feed.json
$python = "C:/Users/SHWETA/AppData/Local/Programs/Python/Python314/python.exe"
$script = "ml_engine/ingest_simulator.py"
& $python $script
Write-Host "Ingest complete."
