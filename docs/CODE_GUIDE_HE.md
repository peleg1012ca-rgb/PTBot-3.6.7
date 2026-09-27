# מפת הקוד — PTBot 3.6.7

`app.py` מחבר את Flask, האבטחה וה־blueprints. `workbench.py` מספק את המסכים וההרצות.

`xss_engine.py` מטפל בגילוי GET, במדיניות ובקצב הבקשות, בהכנת שתי בדיקות קבועות ובסיווג התוצאות.
`xss_browser.py` מריץ תהליך Chromium מוגבל בזמן, מגיש אליו את תגובת השרת מהזיכרון ומשווה את הודעת alert לסמן הייחודי.
`xss_store.py` מוסיף טבלאות progress וראיות; אינו מוחק היסטוריה קודמת.

`scope_engine.py` ו־`policy_engine.py` מחליטים האם הפעולה מותרת; `rate_limit.py` שומר budget בעסקת SQLite.
`execution.py` ממשיך לטפל בבדיקות HTTP, DNS, TLS ו־TCP הקיימות. החיבור לכתובת IP שנבדקה נשמר גם ברכיב XSS.

`templates/base.html` ו־`static/workbench.css` מספקים את העיצוב המשותף. `static/workbench.js` מעדכן סטטוס ריצה. אין שירות frontend חיצוני או תלות ב־CDN.

`lab_xss.py` הוא שרת התרגול המקומי. `tests/test_xss.py` בודק גבולות והרשאות עם רשת מדומה; `scripts/smoke_xss.py` מבצע בדיקות אמיתיות רק נגד שרת מקומי זמני.

תיעוד היסטורי של 1.0 נשמר ב־`docs/legacy` ואינו מתאר את התוספות החדשות.


## Website Recon — 3.6.7

- `recon_ui.py`: מרכז Assessments, טופס הפעלה, תוצאות, סטטוס, ביטול וייצוא JSON.
- `recon_engine.py`: תזמור מודולים, הרשאות, איסוף DNS/HTTP/TLS/CT ותוצאות חלקיות.
- `recon_tools.py`: מתאמי Nmap/WhatWeb/WhatWaf, הגבלת תהליכים ושער HTTP מקומי ליעד המקובע.
- `scripts/whatwaf_passive.py`: ניתוח פסיבי באמצעות חתימות מהתקנת WhatWaf חיצונית.
- `recon_store.py`: טבלת recon_runs, שמירת תוצאות והתאוששות מהפסקת שרת.
- `templates/recon_*.html` ו־`templates/assessments.html`: הממשק.
- `tests/test_recon.py`: תרחישי הרשאות, מכסות, פרסור, תוצאות ונתונים חלקיים.

השם של מסד הנתונים נשאר `data/ptbot-3.5.4.db` לתאימות.
