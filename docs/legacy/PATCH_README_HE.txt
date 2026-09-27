AI-PT-Agent — עדכון מגבלת קצב ותוצאות חקירה

התכולה: database.py, local_http.py, engagements_ui.py, rate_limit.py,
investigation_store.py ו-tests/test_rate_and_investigation.py.
אין בחבילה מסד נתונים, גיבוי או סורקים.

להתקין במכונת Kali כאשר שרת האפליקציה כבוי:

cd /home/peleg/AI-PT-Agent
mkdir -p ~/Downloads/ai-pt-pre-rate-backup
cp -n database.py local_http.py engagements_ui.py ~/Downloads/ai-pt-pre-rate-backup/
unzip -o ~/Downloads/ai-pt-rate-and-results.zip -d .
.venv/bin/python -m unittest discover -s tests -v

הפקודה האחרונה אמורה להריץ 70 בדיקות. רק לאחר מכן להפעיל מחדש את app.py.
init_db תוסיף ארבע טבלאות חדשות בפעם הבאה שהאפליקציה תעלה:
action_reservations, investigation_runs, observations, evidence_refs.
הטבלאות והנתונים הקודמים נשמרים; hash הקובץ החי ישתנה לאחר המיגרציה.

המכסה נספרת בחלון נע של 60 שניות לכל engagement ולכל action_type:
כל הזמנה לפני פתיחת חיבור צורכת מקום, גם אם החיבור נכשל.
פעולה שנדחתה לפני ההזמנה אינה צורכת מקום.
SQLite BEGIN IMMEDIATE מסדר לחיצות מתחרות בתוך תהליך וגם בתהליכים שונים.
במגבלת 10 לדקה, לחיצה 11 תחזיר HTTP 429 ללא חיבור לשרת המעבדה.

תוצאות הבדיקה: response_status, security_headers, cookies, forms,
cors ו-error_disclosure. כל ממצא הוא unreviewed ולא הוכחה לחולשה.
הנתונים נשמרים ככותרות קבועות וסימנים בלבד; הגוף, cookies וערכי כותרות אינם נכתבים.
XSS/HTML injection אינם נבדקים מה-GET הסטטי הנוכחי.

החבילה אינה מתקינה את pt-toolkit-v2 או שולחת בקשות חדשות.
/scan עדיין כבוי; GET נשאר מוגבל ל-http://127.0.0.1:8000/.
