"""KavachBench-IN: a small, hand-written, *held-out* stress test.

Every item below was written by hand with wording that does NOT come from the training templates or
the public corpora.  It exists to answer one question honestly: "does the system still work on
messages it has never seen the style of?"  It is small (so confidence intervals are wide - the
evaluation script prints them) and it is NEVER used for training, threshold selection or rule
weighting.

Fields: text, label (1 scam / 0 legit), sender (optional SMS header), category.
"""
import json
import os

S = []  # scams: (text, sender, category)


def s(text, sender=None, cat="scam"):
    S.append((text, sender, cat))


# ---- bank / KYC / account block --------------------------------------------------------------
s("Dear SBI customer your YONO account will be blocked today. Update PAN now: http://sbi-yono-kyc.co/login", "+919876501234", "bank_kyc")
s("HDFC Bank: Your netbanking is suspended due to pending KYC. Verify within 24 hrs at hdfc-secure-update.top/kyc or account will be closed.", "9810022233", "bank_kyc")
s("Your ICICI credit card reward points worth Rs 9,850 will expire today. Redeem now icici-rewards-claim.xyz", "VK-ICICIR", "reward")
s("Axis bank alert!! your a/c has been temporarily restricted. call 8801234567 immediately to reactivate", "+918801234567", "bank_kyc")
s("Dear user, your Kotak mobile banking is deactivated. Complete re-KYC today http://kotak-kycupdate.in/verify", None, "bank_kyc")
s("Paytm KYC expired. Your wallet will be frozen in 2 hours. Complete video KYC: bit.ly/3xKycPtm", "+917700112233", "bank_kyc")
s("PNB: Your ATM card is blocked. To unblock share your card number, expiry and the OTP you receive.", "+919123456780", "credential_theft")
s("We noticed unusual activity. Confirm your CVV and card PIN by replying to this message to avoid account closure.", None, "credential_theft")
s("Your SBI debit card has been deactivated. Please call our officer at 7011223344 and keep your card details ready.", "+917011223344", "credential_theft")
s("Bank of Baroda: Dear customer PAN not linked, your account will be closed in 24 hours. Click bobkyc-india.online to update", None, "bank_kyc")
s("Urgent: your Aadhaar is not linked with your bank account and subsidy will stop. Link now: aadhaar-bank-link.site/in", None, "bank_kyc")
s("Dear customer your credit limit has been increased to Rs 2,00,000. To activate, share the OTP sent to your number.", "+918899776655", "credential_theft")
s("Your UPI ID will be disabled by NPCI tonight. Verify your UPI PIN at upi-verify-npci.xyz to continue using it.", None, "upi_scam")
# ---- reward / lottery / prize ----------------------------------------------------------------
s("Congratulations!! You are selected as KBC lucky winner of Rs 25,00,000. Contact WhatsApp 9988776655 to claim your prize.", "+919988776655", "reward")
s("You have won a free iPhone 15 from Amazon Great Sale. Claim before it expires: amzn-gift-winner.top", None, "reward")
s("Dear Jio user you won Rs 5000 cashback in lucky draw. Click here to claim jio-lucky-spin.click/win", None, "reward")
s("Flipkart Big Billion Lucky customer! You have been chosen to receive a free smartwatch, pay only Rs 49 delivery http://flipkart-offer.shop/claim", None, "reward")
s("Your mobile number won 1,00,000 GBP in the UK National Lottery. Email your name and bank details to claim.", None, "reward")
s("Free recharge of Rs 599 for all Airtel users till tonight only! Get yours: airtel-free-recharge.live", None, "reward")
# ---- delivery / customs / courier ------------------------------------------------------------
s("India Post: Your parcel is held at the depot due to incomplete address. Update address and pay Rs 25 fee: indiapost-redeliver.top/track", None, "delivery")
s("DHL: shipment 4471883392 has a customs duty of Rs 1,260 pending. Pay within 24 hrs to avoid return: dhl-customs-pay.xyz", None, "delivery")
s("Your package could not be delivered. Reschedule here and pay redelivery charge: https://bluedart-parcel.icu/r/9981", None, "delivery")
s("FedEx notice: a parcel in your name contains illegal items. Call the customs officer on 9090909090 right away.", "+919090909090", "authority")
# ---- authority impersonation / digital arrest -------------------------------------------------
s("This is CBI Mumbai. A parcel booked using your Aadhaar contained narcotics. Join the video call now or an arrest warrant will be issued.", None, "authority")
s("TRAI notice: your mobile number will be disconnected in 2 hours for illegal activity. Press 9 to talk to the officer.", None, "authority")
s("Cyber crime branch: Your SIM is linked to a money laundering case. Do not tell anyone. Contact Inspector Sharma at 8008008000 immediately.", "+918008008000", "authority")
s("Income Tax Dept: legal action will be initiated against you for unpaid tax of Rs 48,200. Pay now via incometax-pay-india.top to avoid arrest.", None, "authority")
s("Supreme Court e-notice: case no 442/2026 filed against you. Download the FIR copy from the link and respond within 3 hrs.", None, "authority")
# ---- job / task / investment ------------------------------------------------------------------
s("Hello, we have a part time job for you. Earn Rs 3000 to 8000 daily by liking YouTube videos. Join our Telegram group t.me/earnfast_hr", None, "job")
s("Work from home, only 2 hrs a day, salary Rs 40,000 a month, no experience needed. WhatsApp 9876512345 to start today.", "+919876512345", "job")
s("Amazon HR: We are hiring for product rating tasks. Complete 3 tasks and receive Rs 500 instantly. Chat with our manager now.", None, "job")
s("Guaranteed 30% returns every week with our VIP crypto trading signals. Limited seats, join the USDT group now.", None, "investment")
s("Dear investor, your IPO allotment is confirmed. Pay the advance fee Rs 4,999 to release shares: ipo-allot-india.xyz", None, "investment")
s("Double your money in 10 days. Invest Rs 10,000 get Rs 20,000. Trusted by thousands, message us on WhatsApp.", None, "investment")
s("Pre-approved personal loan Rs 5 lakh no CIBIL no documents. Pay Rs 1,500 processing fee to receive the amount today.", None, "loan")
s("Instant loan approved! Download our app QuickCash.apk to get money in 5 minutes http://quickcash-loan.shop/app.apk", None, "loan")
# ---- UPI / payments --------------------------------------------------------------------------
s("Hi, I accidentally sent you Rs 5000 on PhonePe. Please approve the collect request I sent to return it.", "+919345678901", "upi_scam")
s("To receive your refund of Rs 1,799 scan the QR code and enter your UPI PIN to accept.", None, "upi_scam")
s("Sir your GPay cashback of Rs 2,000 is pending. Approve the request in your app and enter the PIN to receive.", None, "upi_scam")
# ---- utilities / telecom / fastag / challan --------------------------------------------------
s("Dear consumer your electricity will be disconnected tonight at 9.30 pm as previous bill is not updated. Call 9944001122 right now.", "+919944001122", "utility")
s("TNEB: power supply will be cut tonight for unpaid bill. Pay now: https://tneb-billpay.top/pay", None, "utility")
s("Your FASTag is blacklisted, please re-KYC at fastag-kyc-update.in to avoid double toll charges.", None, "bank_kyc")
s("E-challan of Rs 1,000 issued for your vehicle. Pay within 24 hours to avoid court proceedings: parivahan-echallan.xyz/pay", None, "authority")
s("Your gas connection will be stopped. Update KYC immediately at lpg-kyc-update.online and enter your Aadhaar and bank details.", None, "utility")
s("Your SIM will be blocked in 24 hours. Complete re-verification: http://vi-sim-verify.cc/start", None, "bank_kyc")
s("Dear customer your Airtel number is not verified, services will stop today. Call 9000090000 to avoid disconnection.", "+919000090000", "bank_kyc")
# ---- family / social engineering / remote access ---------------------------------------------
s("Hi mum, I lost my phone and this is my new number. Can you send Rs 15,000 urgently? I will explain later.", "+447911123456", "family")
s("Hello dad, my phone broke, using a friend's number. Please transfer money to this account, it is urgent.", "+919765432100", "family")
s("Your bank has detected malware. Install the AnyDesk app and give us the 9 digit code so our expert can secure your account.", None, "remote_access")
s("Download the SBI Rewards app apk to redeem your 9,980 points before they lapse: sbi-rewards-points.in/SBIRewards.apk", None, "remote_access")
s("PM Kisan 17th installment pending. Install the PM-Kisan app from this link to receive your Rs 2000: pmkisan-update.apk-download.top", None, "remote_access")
s("Insurance bonus Rs 80,000 is ready for you. Share your policy number and bank OTP to receive the payment.", None, "credential_theft")
s("EPFO: your PF withdrawal of Rs 62,000 is on hold. Verify your UAN and OTP at epfo-claims-india.xyz", None, "bank_kyc")
s("Scholarship Rs 25,000 approved for you by the government. Submit Aadhaar and account no at scholar-gov-india.click", None, "reward")
s("Hello this is Priya from HR, we reviewed your resume. Kindly pay Rs 2,000 registration fee to confirm your interview slot.", None, "job")
s("Final warning: your electricity KYC is incomplete and supply will be disconnected. Call 6300112233 now.", "+916300112233", "utility")
s("Dear user, a login attempt was blocked on your account. Secure it immediately by verifying here: secure-login-update.top/id", None, "bank_kyc")
s("Netflix payment failed. Your account will be suspended. Update your card details now: netflix-billing-help.xyz", None, "bank_kyc")
s("Your WhatsApp will expire tomorrow. Verify to continue using for free: whatsapp-verify-gold.top", None, "bank_kyc")
s("RBI notice: your savings account is under review. Provide your net banking user id and password to avoid freeze.", None, "credential_theft")
s("Sir, your cylinder subsidy of Rs 900 is credited but account is inactive. Send your card number and PIN to release.", None, "credential_theft")
s("Get a CIBIL score increase and instant loan, click http://cibil-boost-now.xyz and enter your PAN and bank login.", None, "loan")
s("Hi dear, i am Rachel from london, found your profile, i want to send you a gift parcel but need Rs 6,500 customs, please help", None, "romance")
s("Congrats your number is chosen for Rs 15 lakh Jio lucky draw. To get the amount pay Rs 3,000 tax first.", None, "reward")
s("Your Amazon account has been locked due to suspicious activity. Verify now to unlock: amazon-verify-account.cyou", None, "bank_kyc")
s("Dear customer, last date to update your PAN is today. Account will be freezed. Click: pan-update-income.top", None, "bank_kyc")
s("Order a SIM upgrade to 5G free. Reply with your Aadhaar and OTP to confirm.", None, "credential_theft")
s("Your parcel from Amazon requires verification. Share the OTP sent to your phone with our delivery agent on 9333344444 to release.", "+919333344444", "credential_theft")
s("DEAR CUSTOMER YOUR ACCOUNT HAS BEEN DEBITED RS 49,999. IF NOT YOU CALL 1800-XXX-SUPPORT AT ONCE 9812345670 TO CANCEL", "+919812345670", "bank_kyc")
s("tumhara bijli connection aaj raat kat jayega, bill update nahi hua. abhi 9876543210 pe call karo", "+919876543210", "utility")
s("Aapka SBI account band ho jayega. Abhi KYC update karein: sbi-kyc-new.xyz", None, "bank_kyc")
s("Aapko KBC mein 25 lakh ka inaam mila hai. Claim karne ke liye WhatsApp karein 9871234560", "+919871234560", "reward")
s("Free Aadhaar update camp: click here to book slot and pay Rs 99 booking fee aadhaar-slot-booking.in/pay", None, "bank_kyc")
s("Dear sir your property tax overdue notice served, pay immediately to avoid sealing: mcgm-tax-pay.online", None, "utility")
s("YOUR NUMBER HAS BEEN SELECTED FOR MICROSOFT LUCKY DRAW 8,50,000 USD. SEND YOUR FULL NAME AGE ADDRESS TO CLAIM", None, "reward")
s("Pending refund Rs 3,247 from the Income Tax department. Submit bank details at the link to receive: itr-refund-claim.top/in", None, "refund")
s("Your internet banking password expires today. Reset immediately: http://192.168.44.10/netbank/reset", None, "credential_theft")
s("Kindly verify your identity: send a photo of your Aadhaar and PAN to this number to continue getting pension.", "+919191919191", "credential_theft")
s("Alert: someone tried to use your debit card. Press 1 to speak with the bank fraud team now.", None, "credential_theft")
s("Earn Rs 500 for every friend you invite. Invest only 1000 to start. Join the Telegram channel for daily payouts.", None, "job")
s("Big discount! Buy gold at Rs 10 per gram today only, pay via the link tinyurl.com/gold-10-offer", None, "investment")
s("Sir, mobile tower installation approved on your land, rent Rs 35,000 per month. Pay Rs 5,000 agreement charge first.", None, "advance_fee")
s("Dear student your exam fee payment failed. Pay again at the link, last chance: exam-fee-portal.xyz/pay", None, "bank_kyc")
s("Dear Customer, your account no ending 4421 is blocked due to incomplete verification. Click https://bit.ly/3Zq9kPa", None, "bank_kyc")
s("Your Paytm account is under investigation for suspicious transactions. Install the support app to resolve.", None, "remote_access")
s("Your courier ordered with COD is ready, to confirm delivery send Rs 1 on this UPI id and share the screenshot.", "+919000011111", "upi_scam")

L = []  # legit: (text, sender, category)


def l(text, sender=None, cat="legit"):
    L.append((text, sender, cat))


# ---- bank alerts / OTP -----------------------------------------------------------------------
l("Your OTP for adding a new beneficiary is 482915. This code is valid for 10 minutes. Do not disclose it to anyone, the bank will never ask for it.", "VM-HDFCBK", "otp")
l("INR 1,250.00 debited from Account XX7781 on 14-Nov-26 for UPI-Tea Stall. Avl Bal INR 14,320.55. Report fraud at the official branch.", "AX-ICICIB", "txn")
l("Dear Customer, Rs.18,000.00 has been credited to your A/c no. XXXXXX3342 on 02/11/2026 by NEFT from ACME PVT LTD. -State Bank of India", "VK-SBIINB", "txn")
l("Your credit card statement of Rs 22,415 is due on 05-Dec. Pay on time to avoid late fee. For queries use the app or the number behind your card.", "AD-AXISBK", "txn")
l("Do not share your OTP, PIN, CVV or password with anyone. Axis Bank will never call or SMS to ask for these. Stay safe.", "JD-AXISBK", "awareness")
l("Reminder: Your KYC is due for periodic update. Please visit the branch with your ID, or complete it in the mobile app. We never ask you to share documents on WhatsApp or through links.", "VM-SBIBNK", "awareness")
l("UPI mandate for Rs 649 to Netflix has been paused as per your request. You can resume it from your UPI app.", "VM-PAYTMB", "txn")
l("Payment of Rs 3,450 to Reliance Digital via card ending 9902 was successful. Txn ID 7762110045.", "BZ-KOTAKB", "txn")
l("Your loan EMI of Rs 7,812 will be debited on 5th Dec from your account ending 3308. Maintain sufficient balance to avoid charges.", "VM-IDFCFB", "txn")
l("Rs 500 sent to Ramesh K from your account XX1120 using UPI. UPI Ref 628811230055. If this was not you, block UPI from the app.", "VK-CANBNK", "txn")
l("Your debit card ending 4410 has been blocked as per your request. A replacement will arrive in 7 working days.", "VM-BOBSMS", "txn")
l("Dear member, your PF passbook was updated. Latest balance Rs 1,84,220 as on 31-Oct-26. View on the UMANG app.", "EPFOHO", "gov")
l("Fixed deposit of Rs 50,000 booked successfully at 7.1% for 1 year. Maturity date 14-11-2027. Receipt available in net banking.", "VM-UNIONB", "txn")
# ---- OTPs and service codes ------------------------------------------------------------------
l("847362 is your Swiggy verification code. Never share it with delivery partners or callers.", "VM-SWIGGY", "otp")
l("Your Uber ride OTP is 4417. Please share only with your driver at pickup.", "VK-UBERIN", "otp")
l("Use 593016 as your Google verification code.", "GOOGLE", "otp")
l("Your Amazon delivery OTP is 2275. Please share it with the delivery associate only after receiving your package.", "AM-AMAZON", "otp")
l("Aadhaar OTP is 718203, valid for 10 minutes. Do not share this with anyone. -UIDAI", "UIDAI", "otp")
l("Your IRCTC login OTP is 355612. Do not share.", "IRCTCI", "otp")
# ---- shopping / delivery ---------------------------------------------------------------------
l("Your order #403-7712990 has been packed and will be delivered tomorrow between 10 AM and 2 PM. Track it in the Amazon app.", "AM-AMZNIN", "delivery")
l("Hi Karthik, your Flipkart order for Boat Airdopes was delivered. Rate the product at https://www.flipkart.com/orders", "VK-FLPKRT", "delivery")
l("Your Blue Dart shipment 20118833441 is out for delivery today. Executive Murugan 98400xxxxx will contact you.", "BLUDRT", "delivery")
l("Zomato: Your order from Meghana Foods is on the way, arriving in 25 mins. Pay Rs 460 in cash to the delivery partner.", "ZOMATO", "delivery")
l("Your return for the shoes is picked up. Refund of Rs 2,199 will be credited to your original payment source in 3-5 days. -Myntra", "MYNTRA", "delivery")
l("Hey Divya, your Nykaa order has shipped! Expected by Friday. Track: https://www.nykaa.com/orders/track", "NYKAAA", "delivery")
l("India Post: Speed post article EE123456789IN delivered at Pollachi on 12-11-2026. Thank you.", "INDPST", "delivery")
# ---- telecom ---------------------------------------------------------------------------------
l("Dear customer, your Airtel prepaid plan of Rs 299 expires on 18-Nov. Recharge in the Airtel Thanks app to continue enjoying uninterrupted service.", "AX-AIRTEL", "telecom")
l("You have consumed 90% of your 2GB daily data. Buy a data add-on in the MyJio app.", "JM-JIOINF", "telecom")
l("Your Vi postpaid bill of Rs 599 for Oct is generated. Due date 10-Nov. Pay via the Vi app or at a store.", "VI-VIINFO", "telecom")
# ---- travel / appointments / services --------------------------------------------------------
l("PNR 8456231907 train 12675 Chennai to Coimbatore 14-12-2026. Coach B2 seat 34 CNF. Happy journey. -IRCTC", "IRCTCI", "travel")
l("Web check-in for your IndiGo flight 6E 2145 to Bengaluru is open. Check in at https://www.goindigo.in. Boarding gate closes 45 minutes before departure.", "IndiGo", "travel")
l("Reminder: Your appointment with Dr. Anand is tomorrow 5:30 PM at Sri Ramakrishna Hospital. Reply YES to confirm.", "SRHOSP", "appointment")
l("Your blood test report is ready. Please collect from the lab reception or view on the app with your registered number.", "LALPTH", "appointment")
l("Your BESCOM electricity bill of Rs 1,134 for consumer 8803345123 is due on 20-Nov. Pay on the BESCOM portal or app.", "BESCOM", "utility")
l("LPG refill booked. Your cylinder will be delivered by 20 Nov. Please give delivery code 5521 to the delivery man only.", "INDANE", "utility")
l("Water tank cleaning scheduled in your apartment on Saturday 8 AM - 12 PM. Supply will be off. - Residents Welfare Association", None, "utility")
l("Dear Parent, PTM is scheduled on Saturday 16 Nov at 10 AM. Kindly attend with your ward. - Principal, DAV School", "DAVSCH", "school")
l("Semester end exam timetable has been uploaded in the college portal. Check your department notice board. -COE", "PSGTEC", "school")
l("Your Aadhaar address update request has been approved. You can download the updated e-Aadhaar from myaadhaar.uidai.gov.in.", "UIDAI", "gov")
l("Income Tax Department: Your ITR for AY 2026-27 has been successfully e-verified. Acknowledgement number 118456723. No further action required.", "INCTAX", "gov")
l("Your vaccination slot is booked on 3 Dec at PHC Peelamedu. Please carry your ID. -Health Department", "NHMTN", "gov")
l("Your complaint no 4455/26 about street light has been resolved by the Corporation. Reply 1 if satisfied, 2 if not.", "CORPCH", "gov")
l("Voter ID: your application for correction has been registered. Track status on the Voters Service Portal.", "ECINET", "gov")
# ---- promo from legit brands (official links, not threats) -----------------------------------
l("Domino's: Buy 1 get 1 free on all medium pizzas today. Order on the app or at https://www.dominos.co.in. T&C apply.", "DOMINO", "promo")
l("Myntra End of Reason Sale starts tonight 12 AM! Up to 70% off. Shop at https://www.myntra.com", "MYNTRA", "promo")
l("Big Bazaar Republic Day offer: flat 15% off on grocery above Rs 2000. Valid till 26 Jan. Show this SMS at billing.", "BIGBZR", "promo")
l("HDFC Bank: Pre-approved personal loan offer is available for you in the HDFC Bank MobileBanking app under Offers. Not interested? Reply STOP.", "HDFCBK", "promo")
l("Your Spotify Premium family plan renews on 22 Nov for Rs 179. Manage plan at https://www.spotify.com/account", "SPOTFY", "promo")
l("Welcome to Apollo Pharmacy! Your refill reminder: Metformin due. Order at https://www.apollopharmacy.in", "APOLLO", "promo")
l("Get Rs 100 cashback on your first recharge on PhonePe. Offer valid till 30 Nov. T&C apply.", "PHNEPE", "promo")
# ---- personal / chat -------------------------------------------------------------------------
l("Hi Anu, are we still meeting at 6 near the temple? Let me know if you want me to book the autos.", None, "chat")
l("Bro i am at the bus stand, bus is late by 30 mins. Tell amma i will reach by 9", None, "chat")
l("Can you please send me the project report PDF, my laptop battery died", None, "chat")
l("Happy Birthday Ravi! Wish you all the best, treat when we meet, ok?", None, "chat")
l("Mom I reached office. Will call after lunch. Take your BP tablets.", None, "chat")
l("Machan, DBMS viva is on Monday. Go through normalization and joins ok", None, "chat")
l("Dei where are you? We are waiting at the canteen", None, "chat")
l("Sir, I have uploaded the assignment on classroom. Kindly check and let me know if any changes are required.", None, "chat")
l("Ayyo sorry da missed your call. in a meeting, will ring you in an hour", None, "chat")
l("oye kal ka match dekha? kohli ne kya khela yaar", None, "chat")
l("Don't forget to pay the house rent tomorrow, owner will call you. Send me the receipt.", None, "chat")
l("Transferred Rs 3000 to your account for the trip share, please check", None, "chat")
l("Your cab has arrived. White Swift, TN 38 BC 1209. -Ola", "OLACAB", "travel")
l("Interview confirmed for Wednesday 10:30 AM at our Guindy office. Please bring your resume and ID proof. Regards, HR Team, Zoho", None, "work")
l("Hi, this is Ramesh from Honda Service. Your car is ready for pickup. Total bill Rs 4,820 payable at the counter.", None, "service")
l("Your Swiggy Instamart order is arriving in 10 mins. Your delivery partner Anil is nearby.", "SWIGGY", "delivery")
l("Library notice: the book 'Deep Learning' is overdue by 3 days, fine Rs 15. Please return it at the earliest.", "LIBRRY", "school")
l("Dear shareholder, your dividend of Rs 3.50 per share has been credited to your bank account on 12-Nov-26. -Infosys Ltd", "INFYLT", "txn")
l("Your PhonePe payment of Rs 120 to Chai Point is successful. Ref 8873320094.", "PHONEPE", "txn")
l("Alert: Rs 4,999 debited on your card XX2201 at AMAZON on 09-Nov. If not you, call the bank's official helpline printed on your card.", "ICICIB", "txn")
l("Your SBI Life premium Rs 12,500 due 25 Dec. Pay using the SBI Life app or net banking. Policy no ending 4412.", "SBILIF", "txn")
l("You requested to reset your Instagram password. Your code is 273 841. If you did not request this, ignore this message.", "INSTAG", "otp")
l("Your parcel from Meesho will be delivered today. Please keep cash Rs 349 ready for COD.", "MEESHO", "delivery")
l("Good morning, today's class will be online at 9 AM. Meeting link is shared in the group. - Prof. Kumar", None, "school")
l("Your Dream11 withdrawal of Rs 800 has been processed to your bank account ending 7712. May take 1 working day.", "DRM11", "txn")
l("Congratulations on your marriage anniversary! Wishing you both a lifetime of happiness - from all of us at Sharma family", None, "chat")
l("Congratulations! Your application for the internship at Zoho has been shortlisted. Online test on 18 Nov. Details have been emailed to you.", None, "work")
l("Your Aadhaar-seeded bank account will receive the LPG subsidy of Rs 200 within 3 working days. -Indian Oil", "IOCLPG", "gov")

SCAM_URLS = [
    "http://sbi-yono-kyc.co/login", "https://hdfc-secure-update.top/kyc", "http://icici-rewards-claim.xyz/", "http://paytm-kyc-verify.in/update",
    "https://amazon-verify-account.cyou/login", "http://netflix-billing-help.xyz/pay", "https://www.axis-bank-kyc.online/verify",
    "http://192.168.44.10/netbank/reset", "http://45.33.12.9/sbi/login.php", "https://bit.ly/3Zq9kPa",
    "http://secure-sbi-online.com.verify-user.top/index", "https://sbi.co.in.kyc-update.xyz/login", "https://hdfcbank.com.account-verify.site/login",
    "http://icicibank-secure-login.tk/", "https://amaz0n-india-offers.top/gift", "https://flipkart-lucky-draw.click/winner",
    "http://irctc-refund-ticket.in/claim", "http://epfo-claims-india.xyz/uan", "https://incometax-pay-india.top/pay", "http://uidai-aadhaar-update.top/",
    "https://pmkisan-update.apk-download.top/PM-Kisan.apk", "http://sbi-rewards-points.in/SBIRewards.apk", "http://quickcash-loan.shop/app.apk",
    "https://xn--sbi-9qa.com/login", "http://paypa1-secure.com/signin", "https://gpay-cashback-claim.cc/get", "https://jio-lucky-spin.click/win",
    "http://dhl-customs-pay.xyz/track", "https://indiapost-redeliver.top/track", "https://bluedart-parcel.icu/r/9981",
    "http://tneb-billpay.top/pay", "http://lpg-kyc-update.online/aadhaar", "http://fastag-kyc-update.in/start", "https://parivahan-echallan.xyz/pay",
    "http://kotak-kycupdate.in/verify", "http://bobkyc-india.online/update", "https://aadhaar-bank-link.site/in", "http://upi-verify-npci.xyz/pin",
    "http://vi-sim-verify.cc/start", "https://whatsapp-verify-gold.top/", "https://login-microsoft-office365.account-secure.click/auth",
    "http://secure.paytm.kyc.update-wallet.biz/login", "https://phonepe-reward-center.vip/", "http://www.airtel-free-recharge.live/",
    "https://tinyurl.com/gold-10-offer", "http://cibil-boost-now.xyz/pan", "https://itr-refund-claim.top/in", "http://pan-update-income.top/",
    "https://mcgm-tax-pay.online/", "http://exam-fee-portal.xyz/pay", "https://scholar-gov-india.click/apply", "http://aadhaar-slot-booking.in/pay",
    "http://hdfcbank-netbanking-login.cn/index.php", "https://sbi-online-kyc.co.in.secure-login.top/", "https://icici.login-verify.work/ibanking",
    "http://secure-axisbank.online/login", "http://bankofbaroda-kyc.icu/update", "http://pnb-secure.link/netbanking",
    "https://login.facebook.com.security-check.xyz/", "https://instagram-verified-badge.top/apply", "http://apple-id-locked.support/unlock",
    "https://myntra-sale-gift.shop/claim?ref=881", "http://amazonprize-winner.online/claim.php?id=77",
]
LEGIT_URLS = [
    "https://www.sbi.co.in/web/personal-banking", "https://onlinesbi.sbi/", "https://www.hdfcbank.com/personal/pay/cards", "https://www.icicibank.com/personal-banking/cards/credit-card",
    "https://www.axisbank.com/retail/cards", "https://www.kotak.com/en/personal-banking.html", "https://netbanking.hdfcbank.com/netbanking/", "https://www.amazon.in/gp/your-account/order-history",
    "https://www.flipkart.com/account/orders", "https://www.irctc.co.in/nget/train-search", "https://www.incometax.gov.in/iec/foportal/", "https://myaadhaar.uidai.gov.in/",
    "https://www.epfindia.gov.in/site_en/", "https://www.google.com/search?q=weather", "https://mail.google.com/mail/u/0/#inbox", "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://en.wikipedia.org/wiki/Machine_learning", "https://github.com/pytorch/executorch", "https://www.python.org/downloads/", "https://stackoverflow.com/questions/tagged/numpy",
    "https://www.swiggy.com/restaurants", "https://www.zomato.com/coimbatore", "https://www.myntra.com/men-tshirts", "https://www.paytm.com/", "https://phonepe.com/en/business-solutions.html",
    "https://www.airtel.in/recharge-online", "https://www.jio.com/jio-mobility", "https://www.bsnl.co.in/opencms/bsnl/BSNL/services/mobile/", "https://www.indiapost.gov.in/Pages/Home.aspx",
    "https://www.bluedart.com/tracking", "https://www.delhivery.com/track/", "https://www.dhl.com/in-en/home/tracking.html", "https://www.microsoft.com/en-in/microsoft-365", "https://www.apple.com/in/",
    "https://www.netflix.com/in/", "https://web.whatsapp.com/", "https://www.facebook.com/login/", "https://www.instagram.com/accounts/login/", "https://www.psgitech.ac.in/",
    "https://www.iitm.ac.in/academics", "https://nptel.ac.in/courses", "https://www.nic.in/", "https://www.india.gov.in/", "https://www.mygov.in/", "https://cybercrime.gov.in/", "https://sancharsaathi.gov.in/",
    "https://www.goindigo.in/", "https://www.makemytrip.com/flights/", "https://www.redbus.in/", "https://www.bookmyshow.com/chennai", "https://www.dominos.co.in/", "https://www.nykaa.com/",
    "https://www.bigbasket.com/", "https://www.ola.com/", "https://www.uber.com/in/en/", "https://zerodha.com/", "https://www.timesofindia.com/", "https://www.thehindu.com/news/national/",
    "https://www.ndtv.com/india", "https://pypi.org/project/numpy/", "https://docs.python.org/3/library/", "https://huggingface.co/meta-llama", "https://www.arm.com/", "https://developer.arm.com/",
    "https://arm-education.github.io/Arm-Developer-Labs/",
]


def main(out_dir=os.path.dirname(os.path.abspath(__file__))):
    sms = [dict(text=t, label=1, sender=se, category=c) for t, se, c in S] + [dict(text=t, label=0, sender=se, category=c) for t, se, c in L]
    with open(os.path.join(out_dir, "kavachbench_in.jsonl"), "w") as f:
        for r in sms:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    urls = [dict(url=u, label=1) for u in SCAM_URLS] + [dict(url=u, label=0) for u in LEGIT_URLS]
    with open(os.path.join(out_dir, "kavachbench_urls.jsonl"), "w") as f:
        for r in urls:
            f.write(json.dumps(r) + "\n")
    print(f"KavachBench-IN: {len(S)} scam + {len(L)} legit SMS ; {len(SCAM_URLS)} phishing + {len(LEGIT_URLS)} legit URLs")


if __name__ == "__main__":
    main()
