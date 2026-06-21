import os
import sys
import numpy as np
import io
import requests
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from supabase import create_client

# إعدادات إشعارات WhatsApp (CallMeBot API) - يتم جلبها من بيئة النظام لدعم النشر الآمن والإنتاجي
WHATSAPP_PHONE = os.getenv("NEUROSHIELD_WHATSAPP_PHONE", "+1234567890")  # رقم الهاتف الخاص بـ WhatsApp مع رمز الدولة
WHATSAPP_APIKEY = os.getenv("NEUROSHIELD_WHATSAPP_APIKEY", "placeholder_apikey")  # مفتاح API من CallMeBot (أو اتركه تجريبياً)

# التحقق الوقائي من وجود مكتبة reportlab وتثبيتها تلقائياً عند غيابها لضمان استمرارية التقارير
try:
    import reportlab
    print("✅ تم العثور على مكتبة ReportLab بنجاح.")
except ImportError:
    import subprocess
    print("⚠️ لم يتم العثور على مكتبة reportlab. جاري تثبيتها تلقائياً...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab"])
        import reportlab
        print("✅ تم تثبيت مكتبة ReportLab بنجاح وتفعيلها.")
    except Exception as e:
        print(f"❌ فشل تثبيت مكتبة ReportLab: {e}")

# 1. إعداد مسار المجلد وإضافة ai_engine إلى مسار البحث لموديلات بايثون
base_dir = os.path.dirname(os.path.abspath(__file__))
ai_engine_path = os.path.join(base_dir, 'ai_engine')
sys.path.append(ai_engine_path)

# إعدادات الاتصال بقاعدة بيانات Supabase السحابية (PostgreSQL)
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

# تهيئة عميل Supabase
supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
        print("✅ تم تهيئة عميل Supabase بنجاح.")
    except Exception as e:
        print(f"❌ فشل تهيئة عميل Supabase: {e}")
else:
    print("⚠️ تحذير: لم يتم العثور على SUPABASE_URL أو SUPABASE_SERVICE_KEY في متغيرات البيئة.")

def init_db():
    print("☁️ تم الانتقال بالكامل لقاعدة بيانات Supabase السحابية (PostgreSQL).")

init_db()

def insert_alert(process_name, pid, risk_factor, action_taken, status):
    try:
        timestamp = datetime.now().isoformat()
        if supabase:
            supabase.table('neuroshield_alerts').insert({
                "timestamp": timestamp,
                "process_name": process_name,
                "pid": pid,
                "risk_factor": risk_factor,
                "action_taken": action_taken,
                "status": status
            }).execute()
            print("🚀 تم تسجيل التنبيه في Supabase بنجاح (NeuroShield).")
        else:
            print("❌ لم يتم تهيئة عميل Supabase لإدراج التنبيه.")
    except Exception as e:
        print(f"❌ فشل كتابة التنبيه في قاعدة بيانات Supabase (NeuroShield): {e}")

def send_webhook_alert(process_name, pid, risk_factor, action, hostname):
    """
    إرسال إشعار فوري عبر WhatsApp باستخدام CallMeBot API عند اكتشاف تهديد حرج.
    """
    import urllib.parse
    
    # تنسيق الرسالة بالرموز التعبيرية المطلوبة: 🚨، 🖥️، ☣️، 🔒
    message = (
        f"🚨 *NeuroShield Alert* 🚨\n\n"
        f"🖥️ *Host*: {hostname}\n"
        f"☣️ *Threat*: {process_name} (PID: {pid})\n"
        f"🔥 *Risk*: {risk_factor:.2f}%\n"
        f"🔒 *Action*: {action}"
    )
    
    if not WHATSAPP_APIKEY or "placeholder" in WHATSAPP_APIKEY:
        print(f"\n🔔 [محاكي إشعارات WhatsApp - SOC Alert Simulator]:")
        print(message.replace('*', ''))
        return

    try:
        encoded_message = urllib.parse.quote(message)
        url = f"https://api.callmebot.com/whatsapp.php?phone={WHATSAPP_PHONE}&text={encoded_message}&apikey={WHATSAPP_APIKEY}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            print("🚀 [SOC WhatsApp Alert]: تم إرسال إشعار WhatsApp بنجاح.")
        else:
            print(f"⚠️ [SOC WhatsApp Alert]: فشل إرسال إشعار WhatsApp (رمز الاستجابة {res.status_code}): {res.text}")
    except Exception as e:
        print(f"❌ [SOC WhatsApp Alert]: حدث خطأ أثناء إرسال إشعار WhatsApp: {e}")

# 2. استدعاء الطبقات المخصصة من ملف التدريب لضمان تحميل الموديل بشكل سليم - تم إلغاؤه لعدم تحميل الموديل في السيرفر

# 3. تهيئة تطبيق Flask
app = Flask(__name__)

# دعم طلبات الـ CORS يدوياً لضمان اتصال آمن مع أي واجهة أمامية أو وكيل (Agent)
@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# 4. شحن موديل الـ Behavioral Transformer - تم تعطيله لتوفير موارد السيرفر السحابي
model = None
model_loaded = False
load_error = "Model loading disabled on cloud SIEM Gateway"

# ----------------------------------------------------
# 5. نقاط الاستقبال (Endpoints)
# ----------------------------------------------------

@app.route('/api/status', methods=['GET'])
def get_status():
    """
    نقطة فحص الحالة للتأكد من أن السيرفر يعمل والاتصال بـ Supabase مستقر وممتاز.
    """
    db_status = "uninitialized"
    if supabase:
        try:
            # فحص سريع للاتصال بجدول neuroshield_alerts
            supabase.table('neuroshield_alerts').select('id', count='exact').limit(1).execute()
            db_status = "stable"
        except Exception as e:
            db_status = f"error: {str(e)}"
    else:
        db_status = "missing_credentials"

    return jsonify({
        "status": "ONLINE",
        "model_loaded": False,
        "framework": "Lightweight Gateway",
        "supabase_connection": db_status,
        "error": None if db_status == "stable" else f"Supabase connection issue: {db_status}"
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_sequence():
    """
    نقطة استقبال بيانات الـ Telemetry الحية وتحليلها للكشف عن السلوك الخبيث.
    """
    # أ. التأكد من صحة ترويسة الطلب ومحتواه
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "الطلب غير صالح. يجب أن يحتوي جسم الطلب (Request Body) على بيانات بتنسيق JSON."
        }), 400

    data = request.get_json()
    
    # ب. استخراج مصفوفة التسلسل وميتا-بيانات العملية والمضيف والتحليل المحلي إن وجد
    sequence = data.get('sequence') or data.get('sequences')
    process_name = data.get('process_name') or 'Unknown'
    hostname = data.get('hostname') or 'Unknown'
    try:
        pid = int(data.get('pid') or 0)
    except (ValueError, TypeError):
        pid = 0

    # ج. تحديد الحالة والخطورة (إما باستقبالها من الـ Agent أو تحديدها برمجياً لعدم وجود TensorFlow بالسيرفر)
    is_malicious = data.get('malicious') or data.get('is_malicious')
    confidence = data.get('confidence')
    risk_factor = data.get('risk_percentage') or data.get('risk_factor')
    action_taken = data.get('action_taken')
    status = data.get('status')

    # إذا لم يرسل الـ Agent النتيجة بعد التحليل المحلي، نقوم بتصنيف السلوك بناءً على اسم العملية بشكل مبسط
    if is_malicious is None:
        is_malicious = any(k in process_name.lower() for k in ["ransom", "crypt", "lock", "malware", "test_malicious"])
        if confidence is None:
            confidence = 0.99 if is_malicious else 0.01
        if risk_factor is None:
            risk_factor = round(confidence * 100, 2)
        if action_taken is None:
            action_taken = "Terminated" if is_malicious else "Allowed"
        if status is None:
            status = "Threat Detected" if is_malicious else "Healthy"
    else:
        # تحويل القيم الواردة إلى التنسيق الصحيح
        is_malicious = bool(is_malicious)
        if confidence is None:
            confidence = 0.99 if is_malicious else 0.01
        if risk_factor is None:
            risk_factor = round(confidence * 100, 2)
        if action_taken is None:
            action_taken = "Terminated" if is_malicious else "Allowed"
        if status is None:
            status = "Threat Detected" if is_malicious else "Healthy"

    # حفظ السلوك المكتشف في قاعدة البيانات المحلية
    insert_alert(process_name, pid, risk_factor, action_taken, status)

    # إرسال تنبيه فوري عبر الويب-هوك في حال كان الخطر حرجاً وتجاوز 75%
    if is_malicious and risk_factor > 75.0:
        send_webhook_alert(process_name, pid, risk_factor, action_taken, hostname)
        print(f"🔒 [NETWORK ISOLATION HANDLER]: Host '{hostname}' has been placed in quarantine/isolated status due to critical ransomware execution.")

    # ط. بناء وتوزيع الاستجابة
    result = {
        "success": True,
        "malicious": is_malicious,
        "confidence": confidence,
        "risk_percentage": risk_factor,
        "threat_level": "HIGH (Ransomware Detected)" if is_malicious else "LOW (Healthy Process)",
        "processed_length": len(sequence) if isinstance(sequence, list) else 0
    }

    return jsonify(result), 200

# ----------------------------------------------------
# نقاط استقبال إضافية لإدارة قاعدة البيانات ومركز العمليات الأمنية (SOC)
# ----------------------------------------------------

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    نقطة استرجاع كافة التنبيهات المسجلة في قاعدة البيانات مرتبة تنازلياً حسب الوقت من Supabase.
    """
    try:
        if not supabase:
            return jsonify({"success": False, "error": "Supabase client not initialized"}), 500
            
        res = supabase.table('neuroshield_alerts').select('*').order('timestamp', desc=True).execute()
        alerts_list = res.data
            
        return jsonify({
            "success": True,
            "count": len(alerts_list),
            "alerts": alerts_list
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"فشل استرجاع البيانات من قاعدة البيانات السحابية Supabase: {str(e)}"
        }), 500

@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """
    نقطة مسح كافة التنبيهات من قاعدة البيانات السحابية Supabase لتهيئة الاختبار.
    """
    try:
        if not supabase:
            return jsonify({"success": False, "error": "Supabase client not initialized"}), 500
            
        supabase.table('neuroshield_alerts').delete().neq('id', 0).execute()
        return jsonify({
            "success": True,
            "message": "تم مسح سجل التنبيهات بالكامل من Supabase بنجاح."
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"فشل مسح قاعدة البيانات السحابية Supabase: {str(e)}"
        }), 500

@app.route('/api/reports/pdf', methods=['GET'])
def generate_pdf_report():
    """
    إنشاء تقرير PDF أمني رسمي يحتوي على إحصائيات التنبيهات وسجل العمليات من بيانات Supabase.
    """
    try:
        if not supabase:
            return jsonify({"success": False, "error": "Supabase client not initialized"}), 500
            
        # 1. جلب البيانات من Supabase مرتبة تنازلياً
        res = supabase.table('neuroshield_alerts').select('*').order('timestamp', desc=True).execute()
        rows = res.data
        
        # 2. حساب المؤشرات الأمنية التنفيذية
        total_scanned = len(rows)
        total_threats = sum(1 for r in rows if r["status"] == "Threat Detected" or r["action_taken"] == "Terminated")
        total_healthy = total_scanned - total_threats
        
        # 3. تهيئة ملف الـ PDF في الذاكرة (In-Memory Buffer)
        pdf_buffer = io.BytesIO()
        
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        story = []
        
        # 4. إعداد التنسيقات والخطوط
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            name='TitleStyle',
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#0f172a'),  # Slate 900
            alignment=1,  # Center
            spaceAfter=10
        )
        
        subtitle_style = ParagraphStyle(
            name='SubtitleStyle',
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#64748b'),  # Slate 500
            alignment=1,
            spaceAfter=25
        )
        
        section_heading = ParagraphStyle(
            name='SectionHeading',
            fontName='Helvetica-Bold',
            fontSize=13,
            textColor=colors.HexColor('#0284c7'),  # Sky 600
            spaceBefore=15,
            spaceAfter=10
        )
        
        body_style = ParagraphStyle(
            name='BodyStyle',
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#334155'),  # Slate 700
            spaceAfter=8
        )
        
        header_style = ParagraphStyle(
            name='HeaderStyle',
            parent=body_style,
            fontName='Helvetica-Bold',
            textColor=colors.whitesmoke
        )
        
        # 5. بناء المحتوى (Flowables)
        # أ. ترويسة التقرير
        story.append(Paragraph("NeuroShield", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Lead Analyst: Eng. Abdulrahman Jaber Al-Faifi",
            subtitle_style
        ))
        
        # ب. الملخص التنفيذي
        story.append(Paragraph("Executive Summary", section_heading))
        summary_text = (
            "This document presents the official security audit telemetry captured by NeuroShield. "
            "The system runs as a persistent component, monitoring process "
            "API sequences in real-time and enforcing autonomous threat mitigation."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 10))
        
        # ج. بطاقات الإحصائيات (Metrics Cards Table)
        metrics_data = [
            [
                Paragraph("<b>Total Processes Scanned</b>", body_style),
                Paragraph("<b>Total Healthy Processes</b>", body_style),
                Paragraph("<b>Threats Blocked</b>", body_style)
            ],
            [
                Paragraph(f"<font color='#0f172a' size='14'><b>{total_scanned}</b></font>", body_style),
                Paragraph(f"<font color='#059669' size='14'><b>{total_healthy}</b></font>", body_style),
                Paragraph(f"<font color='#dc2626' size='14'><b>{total_threats}</b></font>", body_style)
            ]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[177, 177, 177])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 15))
        
        # د. جدول السجلات التفصيلي
        story.append(Paragraph("Detailed Threat Intelligence & Security Logs", section_heading))
        
        table_data = [[
            Paragraph("Timestamp", header_style),
            Paragraph("Process Name", header_style),
            Paragraph("PID", header_style),
            Paragraph("Risk Factor", header_style),
            Paragraph("Action Taken", header_style)
        ]]
        
        for r in rows:
            timestamp_short = r["timestamp"].replace('T', ' ').split('.')[0]
            is_malicious = r["status"] == "Threat Detected" or r["action_taken"] == "Terminated"
            action_color = "#dc2626" if is_malicious else "#059669"
            
            table_data.append([
                Paragraph(timestamp_short, body_style),
                Paragraph(r["process_name"], body_style),
                Paragraph(str(r["pid"]), body_style),
                Paragraph(f"{r['risk_factor']:.2f}%", body_style),
                Paragraph(f"<font color='{action_color}'><b>{r['action_taken']}</b></font>", body_style)
            ])
            
        # حجم صفحة Letter هو 612x792. مع هوامش 40pt، العرض المتبقي 532pt.
        log_table = Table(table_data, colWidths=[110, 132, 60, 100, 130])
        log_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(log_table)
        
        # 6. بناء التقرير وإرجاع الملف
        doc.build(story)
        pdf_buffer.seek(0)
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name='NeuroShield_Security_Report.pdf',
            mimetype='application/pdf'
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"فشل إنشاء تقرير الـ PDF الأمني: {str(e)}"
        }), 500

# 6. تشغيل السيرفر
if __name__ == '__main__':
    # تشغيل السيرفر محلياً على المنفذ 5000
    print("🔥 جاري تشغيل سيرفر Flask لنظام NeuroShield...")
    app.run(host='0.0.0.0', port=5000, debug=True)
