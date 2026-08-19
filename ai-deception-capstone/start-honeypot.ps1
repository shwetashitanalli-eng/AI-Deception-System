# Start a local honeypot simulator loop (safe demo)
$python = "C:/Users/SHWETA/AppData/Local/Programs/Python/Python314/python.exe"
$script = "deception_layer/honeypot/honeypot_sim.py"
while ($true) {
    & $python $script
    Start-Sleep -Seconds 30
}
