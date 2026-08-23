# WRITEUP - Offside 11mm (Hydra FC VAR Telemetry)

## Challenge Overview
- **Category:** Web / Forensics / Reversing
- **Target URL:** `https://offside-11mm-ad5cdc1eda42.chals.z0d1ak.org`
- **Provided Files:** `webex_hydra-fc-will-come-back.tar.gz` (contains `hydra_var_telemetry_spec.v3.1.json`), `hydra_uplink.pcapng`
- **Flag:** `zdk{FE3lIN6_BaD_f0R_cr0a7Ia}`

---

## 1. Initial Reconnaissance & Spec Analysis

Visiting the root URL `GET /` returns:
```json
{
  "service": "Hydra Floating VAR Telemetry Gateway",
  "api_version": "v1",
  "protocol_version": "FLOAT-VAR-3.1",
  "incident": {
    "match_id": "HYD-SS-FINAL",
    "subject": "Shakes equalizer review",
    "published_decision": "OFFSIDE",
    "published_margin_mm": 11
  },
  "resources": {
    "fixtures": "/api/v1/fixtures?team=hydra",
    "match_summary": "/api/v1/matches/{id}/summary"
  }
}
```

The provided interchange specification `hydra_var_telemetry_spec.v3.1.json` details the system rules and hidden API endpoints:
1. **Kick Frame Identification Rule**:
   - `ball.acceleration_mps2 >= 20`
   - `ball.foot_ball_distance_mm <= 80`
2. **Keypoint Fusion**:
   - For each keypoint across cameras (`CAM-NORTH`, `CAM-SOUTH`, `CAM-EAST`, `CAM-WEST`), select observation with `maximum_confidence`.
3. **Calibration Model**:
   $$\text{corrected\_x\_mm} = \text{raw\_x\_mm} + \text{longitudinal\_offset\_mm} + \text{round}((\text{deck\_pitch\_deg} - \text{reference\_pitch\_deg}) \times \text{mm\_per\_degree})$$
4. **Eligible Keypoints**:
   - `["head", "left_shoulder", "right_shoulder", "torso", "left_knee", "right_knee", "left_foot", "right_foot"]` (excluding hands/arms).
5. **Offside Determination**:
   - `player_line` = maximum `corrected_x_mm` among eligible keypoints for that player.
   - `defender_line` = 2nd-largest defending player line (behind the goalkeeper).
   - $\text{margin} = \text{attacking\_player\_line\_mm} - \text{defender\_line\_mm}$.
6. **API Endpoints**:
   - `POST /api/v1/compare`: Compares telemetry streams (`raw_tracking`, `deck_imu`, `calibration`, `audit`) across match IDs.
   - `POST /api/v1/appeal`: Submits appeal payload to overturn false decisions and obtain the flag.

---

## 2. Telemetry Extraction & Differential Analysis

By querying `POST /api/v1/compare` with all fixture IDs:
```json
{
  "match_ids": ["HYD-SS-FINAL", "HYD-CAL-EAST-042", "HYD-REHEARSAL-17", "HYD-IU-LEAGUE"],
  "streams": ["raw_tracking", "deck_imu", "calibration", "audit"]
}
```

### Key Findings:
1. **Kick Frame**:
   - Checking all frames in `HYD-SS-FINAL`, frame `154828` matches the kick condition with $a = 24.8\text{ m/s}^2$ and $d = 42\text{ mm}$.
   - At frame `154828`, `deck_imu.pitch_deg` = `0.18` (which matches `reference_pitch_deg = 0.18`, so pitch correction is `0`).
2. **Audit Log & Tampered Calibration**:
   - In `HYD-CAL-EAST-042`, `HYD-REHEARSAL-17`, and `HYD-IU-LEAGUE`, the validated calibration profile for `CAM-EAST` is `EAST-CAL-042` with `longitudinal_offset_mm = 0`.
   - In `HYD-SS-FINAL`, the audit log indicates `hydra-ops` switched `CAM-EAST` to profile `EAST-MATCH-043` with `longitudinal_offset_mm = 48`.
   - Shakes' leading keypoint (`right_shoulder`) was observed exclusively by `CAM-EAST` with highest confidence (`raw_x_mm = 1000`).

---

## 3. Margin Recalculation

At kick frame `154828`:
- **Under Tampered Profile (`EAST-MATCH-043`, +48mm)**:
  - Shakes (`SUPA STRIKAS`): $1000 + 48 = 1048\text{ mm}$
  - Defending Players (`HYDRA`):
    - `THE-PLUG` (Goalkeeper): $1500\text{ mm}$
    - `SKIPPER` (2nd Defender): $1037\text{ mm}$
    - `RIPPLE-WHITE`: $900\text{ mm}$
  - Defender Line = $1037\text{ mm}$
  - Margin = $1048 - 1037 = +11\text{ mm}$ $\to$ **OFFSIDE** (Manipulated).

- **Under Validated Profile (`EAST-CAL-042`, 0mm)**:
  - Shakes (`SUPA STRIKAS`): $1000 + 0 = 1000\text{ mm}$
  - Defender Line (`SKIPPER`): $1037\text{ mm}$
  - Corrected Margin = $1000 - 1037 = -37\text{ mm}$ $\to$ **ONSIDE**.

---

## 4. Submitting Appeal & Exploit Script

```python
import urllib.request
import json

BASE_URL = "https://offside-11mm-ad5cdc1eda42.chals.z0d1ak.org"

appeal_payload = {
    "match_id": "HYD-SS-FINAL",
    "kick_frame": 154828,
    "bad_sensor": "CAM-EAST",
    "correct_profile": "EAST-CAL-042",
    "corrected_margin_mm": -37
}

req = urllib.request.Request(
    f"{BASE_URL}/api/v1/appeal",
    data=json.dumps(appeal_payload).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read().decode("utf-8"))
    print(result)
```

### Server Response:
```json
{
  "status": "accepted",
  "decision": "ONSIDE",
  "flag": "zdk{FE3lIN6_BaD_f0R_cr0a7Ia}"
}
```
