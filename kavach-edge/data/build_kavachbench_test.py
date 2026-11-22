"""KavachBench-IN-TEST: LOCKED hand-written test set (written before fusion weights / thresholds were fitted).

Protocol:  kavachbench_in.jsonl  = DEV   (seen during error analysis; used to fit fusion + thresholds)
           kavachbench_in_test.jsonl = TEST (never used for any fitting or selection; reported separately)
Both sets were written by the same author, so they share a "writer's style" - a limitation we state in the
report.  The test set is small (n~100), so every number in the report carries a Wilson confidence interval.
"""
import json
import os

S, L = [], []


def s(t, sender=None, c="scam"):
    S.append((t, sender, c))


def l(t, sender=None, c="legit"):
    L.append((t, sender, c))


# ------------------------------------------------------------------ scams
s("Your HDFC account is on hold. Complete Video-KYC in 30 mins or lose access: hdfc-videokyc-india.top/start", None, "bank_kyc")
s("State Bank alert: Rs 24,500 will be debited today. If not authorised, call 9167001122 immediately to stop it.", "+919167001122", "bank_kyc")
s("Dear Axis customer, your debit card expires tomorrow. Click axis-cardrenew.online to renew free of charge.", None, "bank_kyc")
s("Sir/Madam your Canara Bank savings account is flagged inactive. Reactivate now by sending your ATM PIN to this number.", "+918123456789", "credential_theft")
s("Rs 9,999 refund pending from Paytm. Enter your UPI PIN on the page to receive it: paytm-refund-center.xyz", None, "upi_scam")
s("IRCTC refund of Rs 1,120 is waiting. Verify your card details to receive: irctc-refund-help.in/claim", None, "refund")
s("Your Jio SIM will be deactivated within 3 hrs. Update Aadhaar now: jio-aadhaar-verify.cc", None, "bank_kyc")
s("Hey this is Amit from SBI credit card team. Your reward points 12,500 are expiring, share OTP to redeem them.", "+919811223344", "credential_theft")
s("Congrats! You've won Tata Safari in Amazon lucky draw. Pay Rs 4,500 shipping charges to get your car.", None, "reward")
s("YOU ARE SELECTED for Rs 50,000 monthly salary home based job. Telegram only: t.me/jobs_wfh_india", None, "job")
s("Earn Rs 800 per task. Review hotels on Google Maps and get paid daily. Message our manager on WhatsApp 9000012345", "+919000012345", "job")
s("Join our premium stock market group. 100% sure shot tips, 5x returns in 15 days. Limited slots, DM now.", None, "investment")
s("Your electricity connection is scheduled for disconnection tonight 10 pm. Pay Rs 2,300 immediately via bijli-pay-now.top", None, "utility")
s("Gas subsidy of Rs 750 is blocked. Update KYC at lpg-subsidy-kyc.site and enter your account number and PIN.", None, "utility")
s("Your Delhivery package is stuck due to wrong pincode. Update address and pay Rs 30: delhivery-address-fix.top/u", None, "delivery")
s("USPS: your parcel can't be delivered, confirm address within 12 hrs https://usps-redelivery.cyou/track", None, "delivery")
s("Mumbai Police Cyber Cell: complaint registered against your number for obscene calls. Contact Inspector Rane 9004455667 or face arrest.", "+919004455667", "authority")
s("ED Notice: Your PAN is used in a hawala transaction. To avoid arrest, join this video call and cooperate.", None, "authority")
s("TRAI: Your mobile number will be blocked today as you have received 3 complaints. Press 1 to speak to the TRAI executive.", None, "authority")
s("Customs department: A package from Dubai in your name has been seized with illegal items. Pay Rs 38,000 clearance fee today.", None, "authority")
s("hi mom this is my new whatsapp, my phone fell in water. i need to pay a bill urgently can you transfer 20000 to this acct", "+447455512345", "family")
s("Dear sir please approve the collect request of Rs 1 to confirm your delivery address. Enter UPI PIN to continue.", None, "upi_scam")
s("Download the 'RTO e-Challan' app from this link and pay your pending challan today: rto-challan-app.in/RTO.apk", None, "remote_access")
s("Your phone is infected with 5 viruses. Install the security app now to clean your device: https://mobile-clean-sec.icu/scan.apk", None, "remote_access")
s("To fix the issue install QuickSupport and share the ID number shown with our technician.", None, "remote_access")
s("Your Netflix subscription is on hold. Please update the payment method now at netflix-payment-hold.xyz to avoid cancellation.", None, "bank_kyc")
s("PM Awas Yojana subsidy Rs 2.67 lakh approved in your name. Register your bank details here to receive: pmay-subsidy-india.site", None, "reward")
s("Instant personal loan up to Rs 3 lakh in 10 minutes, zero documents. Pay Rs 999 insurance fee to disburse.", None, "loan")
s("We are Flipkart HR. Work 1 hour daily from home and earn Rs 15,000 per week. Send 'JOIN' on WhatsApp.", None, "job")
s("Final notice: your SBI account will be blocked as PAN is not updated. Update immediately at sbi-pan-update-now.xyz", None, "bank_kyc")
s("Apple ID locked due to suspicious sign-in. Verify identity within 24 hours: appleid-unlock-verify.top", None, "bank_kyc")
s("You are the lucky winner of Rs 8,00,000 from Reliance Jio anniversary lottery. WhatsApp +91 9811100000 with your name and Aadhaar.", "+919811100000", "reward")
s("Your Aadhaar card has been suspended. Call 1800 now to get it reactivated or face a Rs 10,000 fine.", None, "authority")
s("aapka bijli bill pending hai, aaj raat 9 baje connection kat jayega. is number pe turant sampark karein 9988112233", "+919988112233", "utility")
s("Aapka SBI YONO account block ho gaya hai. Abhi unblock karein: yono-sbi-unblock.in", None, "bank_kyc")
s("Dear customer you have won a cashback of Rs 5000. Scan the QR and enter your PIN to receive in your bank account.", None, "upi_scam")
s("Hello, I'm calling from LIC. Your policy bonus of Rs 1,80,000 is ready. Share your Aadhaar and OTP to get it credited.", None, "credential_theft")
s("Crypto giveaway: send 0.1 BTC to the address below and get 1 BTC back. Hurry, offer ends in 1 hour.", None, "investment")
s("KYC expired for your Airtel Payments Bank wallet. Balance will be frozen in 2 hours. Update at airtel-bank-kyc.live/u", None, "bank_kyc")
s("Dear Sir, your driving license is suspended. Pay penalty of Rs 5,000 at parivahan-penalty.top within 24 hrs to avoid legal action.", None, "authority")
s("Get Rs 500 for every referral! Download Winzo Gold APK from our site and earn unlimited: winzo-gold-earn.site/get.apk", None, "reward")
s("Your WhatsApp account will be suspended. To keep it, forward this verification code to us: reply with the 6 digit code you receive.", None, "credential_theft")
s("The tax department has detected mismatch in your returns. Pay Rs 14,000 penalty today to avoid prosecution: https://incometax-penalty.work", None, "authority")
s("Hi dear, this is Priya. I found your number from the group. Can we talk? Message me on this WhatsApp link wa.me/919000011122", None, "romance")
s("Your parcel was returned. To receive again pay Rs 49 on our website and enter your debit card details: parcel-return-india.icu", None, "delivery")
s("EPFO: claim of Rs 78,000 rejected. Re-submit with Aadhaar OTP and bank password at epf-claim-resubmit.click", None, "bank_kyc")
s("Scholarship for SC/ST students Rs 30,000 approved. Pay Rs 500 processing fee to release it.", None, "reward")
s("Mobile tower on your land: monthly rent Rs 45,000 + advance Rs 15 lakh. Pay Rs 8,500 registration fee to confirm.", None, "advance_fee")
s("Urgent!! Your bank account has been hacked. Transfer your money to this safe account immediately to protect it.", None, "authority")
s("Dear client, ICICI Bank is upgrading its system. Re-enter your net banking user ID and password at icici-system-upgrade.xyz.", None, "credential_theft")

# ------------------------------------------------------------------ legit
l("Your one time password is 905512 for adding Priya S as a payee. Valid for 5 minutes. Never share your OTP with anybody.", "VM-HDFCBK", "otp")
l("Rs 2,300.00 was debited from your A/c XX4412 on 18-Nov-26 at AMAZON PAY INDIA. Avl bal Rs 31,882.10. -Axis Bank", "AX-AXISBK", "txn")
l("Your SBI card ending 7734 was used for Rs 1,845 at BIG BAZAAR on 20 Nov. If this is not you, please block the card in the SBI Card app.", "VM-SBICRD", "txn")
l("Dear Customer, your fixed deposit no 5520 has been renewed for 12 months at 7.25%. Thank you for banking with us.", "VK-IOBCHN", "txn")
l("UPI: Rs 75 paid to Tamil Selvi Stores on 19-11-26. UPI ID 9876xxxx@ybl. Ref 833291044118.", "PHONEPE", "txn")
l("Your OTP to verify the mobile number is 6027. Please do not share it with anyone. -Zepto", "ZEPTOS", "otp")
l("Amazon: your package arrives today by 8 PM. For delivery please share OTP 4471 with our delivery associate only.", "AM-AMAZON", "delivery")
l("Your Swiggy order #8841234 is on the way. Keep Rs 280 ready if paying by cash. Thanks for ordering!", "SWIGGY", "delivery")
l("Fedex: your shipment 7746 2231 9902 is out for delivery. Track at https://www.fedex.com/fedextrack", "FEDEX", "delivery")
l("Hi Ravi, your ride is confirmed. Driver Ramesh, TN 37 CY 5521, arriving in 4 min. Share OTP 3382 at pickup.", "OLACAB", "travel")
l("Train 12631 Nellai Express PNR 4418837721 status CNF/B3/41. Happy journey. Download the IRCTC Rail Connect app for live status.", "IRCTCI", "travel")
l("Your flight 6E 6142 departs at 06:35 from Terminal 1. Check-in counters close 60 minutes before departure. Safe travels.", "INDIGO", "travel")
l("Reminder: Your daughter's school fee Rs 14,500 is due 25-Nov. Pay online using the school portal. - Accounts", "SCHOOL", "school")
l("Dear students, tomorrow's CAT-1 will begin at 9:30 AM sharp in block C. Bring your ID card and hall ticket.", None, "school")
l("Dr. Meena's clinic: your appointment is tomorrow at 11:15 AM. Please reply 1 to confirm or 2 to cancel.", "DRMEEN", "appointment")
l("Your lab test results are ready. Please visit the diagnostic centre or log in to the patient app to view them.", "THYROC", "appointment")
l("The water supply in Sector 14 will be shut from 10 AM to 2 PM on Thursday for pipeline repair. Kindly cooperate. -Jal Board", "JALBRD", "utility")
l("Your BESCOM bill for Oct 2026 is Rs 1,640. Last date 28 Nov. Pay at bescom.co.in or the BESCOM app.", "BESCOM", "utility")
l("PM-KISAN: the 17th installment has been credited to your bank account on 20 Nov. Check status on the official portal.", "PMKISN", "gov")
l("Your passport application ARN 12345 has been received. Police verification will be scheduled. Track on Passport Seva portal.", "PSPORT", "gov")
l("Your ration card correction request is approved. New card will be sent to your address in 15 working days.", "TNPDS", "gov")
l("IMPORTANT: Banks never ask for OTP/PIN. Beware of fraud calls claiming KYC update. If in doubt, visit your home branch.", "SBIINB", "awareness")
l("RBI says: Never share card details, CVV or OTP with anyone. Report cyber fraud on 1930. - Reserve Bank of India", "RBIKAR", "awareness")
l("Don't fall for fake 'KBC lottery' messages. Genuine lotteries never ask for fees. Stay safe online. - Cyber Crime Cell, Tamil Nadu", "TNCYBR", "awareness")
l("Hi Karthik, thanks for your payment of Rs 499. Your Spotify Premium is active till 20-Dec. Enjoy!", "SPOTFY", "promo")
l("Diwali Dhamaka! Flat 30% off on TV, laptops and phones at Croma. Visit your nearest store. T&C apply. Offer till 10 Nov.", "CROMAA", "promo")
l("Hello, your Dominos order is being prepared and will arrive in 30 minutes. Track at https://www.dominos.co.in/track", "DOMINO", "delivery")
l("Welcome to Jio! Your new SIM is activated. Dial 199 for help or download the MyJio app for recharge and offers.", "JIOINF", "telecom")
l("Airtel: Your postpaid bill of Rs 799 is due on 5 Dec. View and pay from the Airtel Thanks app. Ignore if already paid.", "AIRTEL", "telecom")
l("Hey are you free this weekend? We are planning a trip to Ooty. Let me know by tonight so I can book the rooms.", None, "chat")
l("machan machi where are you, exam hall la unnaku seat number 214 da", None, "chat")
l("Appa, I have reached Bangalore. Will call you in the evening after settling in.", None, "chat")
l("Hello sir, I have shared the assignment on Google classroom. Please let me know if anything is missing.", None, "chat")
l("bhai wo wala notes bhej de jo kal professor ne diya tha, mera phone mein save nahi hua", None, "chat")
l("Can you transfer the Rs 5000 for the rent today? I will share the receipt after paying the owner.", None, "chat")
l("Mom, doctor said the report is normal. Dont worry. I will tell you the details when I come home", None, "chat")
l("The interview is scheduled for Thursday 3 PM via Google Meet. The link has been sent to your registered email id. - HR, Freshworks", None, "work")
l("Congratulations on your promotion Kavya! Well deserved. Lunch is on you :)", None, "chat")
l("Congratulations! You have been selected for the NPTEL Star Performer certificate. Details on the NPTEL portal.", "NPTELS", "school")
l("Dear Customer, your Credit Card payment of Rs 8,000 has been received. Thank you. -ICICI Bank", "ICICIB", "txn")
l("Please note: Dividend of Rs 12 per share credited to your demat linked bank a/c on 18-Nov. -Tata Motors", "TATAMT", "txn")
l("Your Zerodha account was credited with Rs 25,000 on 21-Nov. Fund available for trading.", "ZERODH", "txn")
l("Your electricity meter will be replaced on 22 Nov between 10 AM and 1 PM. Please keep the premises accessible. - TANGEDCO", "TNEB", "utility")
l("Your gas cylinder has been dispatched. Delivery code is 7731. Please share it only with the delivery person.", "BPCLPG", "utility")
l("Update on your complaint 77812: our engineer will visit tomorrow between 9 AM and 6 PM. Please keep your phone reachable.", "ACTFIB", "service")
l("Netflix: a new device signed in to your account. If it was you, no action is needed. Otherwise manage devices at netflix.com/account", "NETFLX", "otp")
l("KYC update reminder: please update your KYC at your nearest ICICI Bank branch or via iMobile Pay app. We will not ask for documents by SMS or call.", "ICICIB", "awareness")
l("Order shipped! Your Myntra package will reach you by Tuesday. Track: https://www.myntra.com/track/884412", "MYNTRA", "delivery")

SCAM_URLS = [
    "http://hdfc-videokyc-india.top/start", "https://axis-cardrenew.online/", "https://paytm-refund-center.xyz/refund?id=88", "http://irctc-refund-help.in/claim",
    "http://jio-aadhaar-verify.cc/", "https://netflix-payment-hold.xyz/update", "http://sbi-pan-update-now.xyz/login", "https://appleid-unlock-verify.top/verify",
    "http://airtel-bank-kyc.live/u", "https://parivahan-penalty.top/pay", "https://icici-system-upgrade.xyz/login", "http://epf-claim-resubmit.click/",
    "https://rto-challan-app.in/RTO.apk", "https://mobile-clean-sec.icu/scan.apk", "https://winzo-gold-earn.site/get.apk", "http://pmay-subsidy-india.site/register",
    "https://incometax-penalty.work/pay", "http://usps-redelivery.cyou/track", "https://delhivery-address-fix.top/u", "http://bijli-pay-now.top/",
    "https://lpg-subsidy-kyc.site/", "https://parcel-return-india.icu/pay", "http://yono-sbi-unblock.in/", "http://secure-hdfcbank.net.login-verify.cc/index.php",
    "https://sbi.co.in.netbanking-secure.top/", "http://103.77.12.45/icici/login.html", "https://tinyurl.com/yjk82kh9", "https://bit.ly/4abXyZ1", "https://wa.me/919000011122",
    "https://kotakmahindra-bank-kyc.xyz/update", "https://paytm.com.wallet-kyc-center.top/", "http://amazon-prime-gift.work/claim?src=sms",
]
LEGIT_URLS = [
    "https://www.hdfcbank.com/personal/borrow/popular-loans", "https://netbanking.hdfcbank.com/", "https://retail.onlinesbi.sbi/retail/login.htm", "https://www.sbicard.com/en/personal/credit-cards.page",
    "https://www.fedex.com/fedextrack", "https://www.dominos.co.in/track", "https://www.myntra.com/track/884412", "https://bescom.karnataka.gov.in/", "https://www.tangedco.gov.in/",
    "https://www.passportindia.gov.in/AppOnlineProject/online/procFormSubmit", "https://pmkisan.gov.in/", "https://nptel.ac.in/noc/", "https://www.netflix.com/account", "https://www.spotify.com/in-en/premium/",
    "https://www.zerodha.com/", "https://kite.zerodha.com/", "https://www.airtel.in/bill-payment", "https://www.jio.com/selfcare/", "https://www.croma.com/", "https://www.tatamotors.com/investors/",
    "https://www.google.com/maps", "https://docs.google.com/document/d/1AbC/edit", "https://meet.google.com/abc-defg-hij", "https://classroom.google.com/", "https://www.linkedin.com/in/someone",
    "https://www.freshworks.com/careers/", "https://learn.microsoft.com/en-us/azure/", "https://medium.com/@someone/a-post", "https://www.coursera.org/learn/machine-learning", "https://www.udemy.com/course/python/",
    "https://www.bbc.com/news", "https://www.reuters.com/world/india/", "https://www.moneycontrol.com/", "https://economictimes.indiatimes.com/", "https://www.hindustantimes.com/", "https://scroll.in/",
    "https://www.zoho.com/mail/", "https://www.tcs.com/", "https://www.infosys.com/", "https://www.wipro.com/", "https://www.psgtech.edu/", "https://www.annauniv.edu/", "https://www.iitd.ac.in/", "https://www.isro.gov.in/",
]


def main(out_dir=os.path.dirname(os.path.abspath(__file__))):
    sms = [dict(text=t, label=1, sender=se, category=c) for t, se, c in S] + [dict(text=t, label=0, sender=se, category=c) for t, se, c in L]
    with open(os.path.join(out_dir, "kavachbench_in_test.jsonl"), "w") as f:
        for r in sms:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    urls = [dict(url=u, label=1) for u in SCAM_URLS] + [dict(url=u, label=0) for u in LEGIT_URLS]
    with open(os.path.join(out_dir, "kavachbench_urls_test.jsonl"), "w") as f:
        for r in urls:
            f.write(json.dumps(r) + "\n")
    print(f"KavachBench-IN-TEST: {len(S)} scam + {len(L)} legit SMS ; {len(SCAM_URLS)} phishing + {len(LEGIT_URLS)} legit URLs")


if __name__ == "__main__":
    main()
