# app.py
from flask import Flask, jsonify, request, render_template
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import timedelta
import logging

from db import init_db, upsert_indicator, record_feed_run_start, record_feed_run_end, get_connection
from feeds import fetch_urlhaus_recent, fetch_spamhaus_all

app = Flask(__name__)

# --- Logging (nice to see scheduler logs) ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mini-tip")

# --- Feed runner helpers ---
def run_urlhaus_job():
    run_id = record_feed_run_start("urlhaus")
    count = 0
    try:
        indicators = fetch_urlhaus_recent()
        for ind in indicators:
            upsert_indicator(ind)
            count += 1
        record_feed_run_end(run_id, count, "success", None)
        logger.info(f"URLhaus job: ingested {count} indicators.")
    except Exception as e:
        record_feed_run_end(run_id, count, "error", str(e))
        logger.exception("URLhaus job failed")

def run_spamhaus_job():
    run_id = record_feed_run_start("spamhaus")
    count = 0
    try:
        indicators = fetch_spamhaus_all()
        for ind in indicators:
            upsert_indicator(ind)
            count += 1
        record_feed_run_end(run_id, count, "success", None)
        logger.info(f"Spamhaus job: ingested {count} indicators.")
    except Exception as e:
        record_feed_run_end(run_id, count, "error", str(e))
        logger.exception("Spamhaus job failed")

def run_all_feeds():
    run_urlhaus_job()
    run_spamhaus_job()

# --- Scheduler setup ---
scheduler = BackgroundScheduler()

def start_scheduler():
    # Fetch URLhaus every hour; Spamhaus every 6 hours (they change less often)
    scheduler.add_job(run_urlhaus_job, IntervalTrigger(hours=1), id="urlhaus_job", replace_existing=True)
    scheduler.add_job(run_spamhaus_job, IntervalTrigger(hours=6), id="spamhaus_job", replace_existing=True)
    scheduler.start()
    logger.info("Scheduler started.")

# --- Flask routes ---
@app.route("/")
def home():
    # Show a minimal UI
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM indicators;")
    total = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM indicators WHERE type='url';")
    total_urls = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM indicators WHERE type='cidr';")
    total_cidrs = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM indicators WHERE source LIKE 'spamhaus%';")
    total_spamhaus = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM indicators WHERE source='urlhaus';")
    total_urlhaus = cur.fetchone()["c"]

    conn.close()
    return render_template("index.html",
                           total=total,
                           total_urls=total_urls,
                           total_cidrs=total_cidrs,
                           total_spamhaus=total_spamhaus,
                           total_urlhaus=total_urlhaus)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/indicators")
def indicators():
    """
    Returns JSON of indicators with basic filters:
      /indicators?q=evil.com&type=url&source=urlhaus&limit=50
    """
    q = request.args.get("q", "").strip()
    type_ = request.args.get("type", "").strip()
    source = request.args.get("source", "").strip()
    limit = int(request.args.get("limit", 50))

    sql = "SELECT type, value, source, first_seen, last_seen, tags, confidence, status FROM indicators WHERE 1=1"
    params = []
    if q:
        sql += " AND value LIKE ?"
        params.append(f"%{q}%")
    if type_:
        sql += " AND type = ?"
        params.append(type_)
    if source:
        sql += " AND source = ?"
        params.append(source)
    sql += " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/feeds/run", methods=["POST"])
def manual_run():
    """
    Manually kick off both feeds (synchronous, simple demo).
    """
    run_all_feeds()
    return jsonify({"message": "Feeds fetched."})

if __name__ == "__main__":
    # Important in dev: avoid Flask reloader starting scheduler twice
    init_db()
    start_scheduler()
    # Don't use the auto-reloader here to keep only one scheduler
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
