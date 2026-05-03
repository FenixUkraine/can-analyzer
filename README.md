python main.py auto --root kia --out out_can_scan --min-state-transitions 2
python main.py auto --root mazda --out out_can_scan --drop-ids-with-too-many-changing-bits --max-changing-bits-per-id 8 --min-state-transitions 2
python main.py auto --root mazda --out out_can_scan --drop-ids-with-too-many-changing-bits --max-changing-bits-per-id 4 --min-state-transitions 2
python main.py auto --root kia --out out_can_scan --drop-ids-with-too-many-changing-bits --max-changing-bits-per-id 4 --min-state-transitions 2 --command-button-window-ms 250 --no-command-include-context-frames
python main.py auto --root mazda --out out_can_scan --drop-ids-with-too-many-changing-bits --max-changing-bits-per-id 4 --min-state-transitions 2 --command-button-window-ms 250 --no-command-include-context-

python main.py auto --root kia --out out_can_scan --drop-ids-with-too-many-changing-bits --max-changing-bits-per-id 4 --min-state-transitions 2 --command-button-window-ms 250 --no-command-include-context-frames --command-button-min-near-ratio 0.55 --command-state-max-payload-events 1 --command-best-max-per-event 8