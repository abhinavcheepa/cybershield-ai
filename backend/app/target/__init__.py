"""The deliberately-vulnerable 'student site' — the real attack target.

SAFETY / SCOPE
--------------
This sub-app is intentionally insecure. That is the whole point: it is the
practice target students own, so real attacks launched from the CyberShield
control panel actually land somewhere and students feel the impact.

Hard rules, enforced in code:
  * It only ever runs inside this lab process.
  * The attack runner's target is fixed by server config (`TARGET_BASE_URL`);
    no request can point an attack at any other host.
  * It stores no real credentials or personal data — only lab accounts the
    students create for the exercise.

Do not deploy this as anything other than a throwaway classroom target.
"""
