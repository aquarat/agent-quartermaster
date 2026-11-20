# Sourced by both local interop suites. Only their own throwaway daemon is
# stopped/restarted; the fleet-side binary and its enrollment are unchanged.
personal_cutover() {
	local pid=$1 mode
	for mode in organisations-cutover serve; do
		kill "$pid"; wait "$pid" || true
		"$AQMASD" -config "$T/config.toml" "$mode" >"$T/$mode.log" 2>&1 &
		pid=$!; PIDS+=("$pid")
		for _ in $(seq 100); do curl -fsS "http://127.0.0.1:$PW/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
		curl -fsS "http://127.0.0.1:$PW/healthz" >/dev/null || { cat "$T/$mode.log"; fail "$mode did not start"; }
		if [[ $mode == organisations-cutover ]]; then
			if "$AQMAS" list >"$T/fenced.out" 2>&1; then fail 'agent reads were not fenced'; fi
			owner activate-personal || fail 'signed personal cutover'
		fi
	done
}
