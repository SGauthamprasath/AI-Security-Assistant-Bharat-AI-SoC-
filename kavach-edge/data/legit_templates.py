"""Synthetic *legitimate* Indian SMS (hard negatives).

Why this exists: the public ham corpora we can reach (UCI SMS Spam) are casual UK/Singapore chat.
A classifier trained only on those flags every bank OTP / debit alert / courier update as a scam,
which is the single worst false-alarm failure mode in India.  These templates (banks, UPI, OTPs,
telecom, e-commerce, railways, utilities, schools, appointments, Hinglish chat, official-link promos)
supply the formal-but-legitimate class.  They are deliberately *not* reused in the hand-written
evaluation benchmark (data/kavachbench_in.jsonl), which has different wording written separately.
"""
from __future__ import annotations

import random
from typing import List

BANKS = ["HDFC Bank", "SBI", "ICICI Bank", "Axis Bank", "Kotak Bank", "Bank of Baroda", "Canara Bank", "PNB", "IDFC FIRST Bank", "Union Bank", "Federal Bank", "IndusInd Bank", "Yes Bank"]
MERCH = ["Swiggy", "Zomato", "Amazon", "Flipkart", "BigBasket", "Myntra", "Uber", "Ola", "IRCTC", "BookMyShow", "Netflix", "Reliance Smart", "DMart", "Apollo Pharmacy", "Croma", "Blinkit", "Zepto", "Nykaa", "MakeMyTrip", "RedBus"]
COURIERS = ["Delhivery", "Blue Dart", "Ecom Express", "DTDC", "India Post", "Xpressbees", "Amazon Shipping", "Ekart"]
TELCOS = ["Airtel", "Jio", "Vi", "BSNL"]
NAMES = ["Rahul", "Priya", "Arun", "Kavya", "Suresh", "Anita", "Vikram", "Meena", "Karthik", "Divya", "Rohit", "Sneha", "Manoj", "Lakshmi", "Imran", "Gurpreet", "Ananya", "Sathish"]
CITIES = ["Chennai", "Coimbatore", "Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Pune", "Kolkata", "Jaipur", "Madurai", "Kochi", "Lucknow"]
SITES = {"HDFC Bank": "hdfcbank.com", "SBI": "sbi.co.in", "ICICI Bank": "icicibank.com", "Axis Bank": "axisbank.com", "Kotak Bank": "kotak.com", "PNB": "pnbindia.in"}


def _n(r, a, b):
    return r.randint(a, b)


def _last4(r):
    return "".join(str(r.randint(0, 9)) for _ in range(4))


def _amt(r):
    return random.choice(["{:,}".format(r.randint(10, 9999)), "{:,}.{:02d}".format(r.randint(100, 99999), r.randint(0, 99))])


def _ref(r, n=12):
    return "".join(r.choice("0123456789") for _ in range(n))


def _date(r):
    return r.choice(["{:02d}-{:02d}-{}".format(r.randint(1, 28), r.randint(1, 12), r.choice([24, 25, 26])), "{:02d}{}{}".format(r.randint(1, 28), r.choice(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]), r.choice([24, 25, 26]))])


def _time(r):
    return "{:02d}:{:02d}".format(r.randint(0, 23), r.randint(0, 59))


def gen(n: int, seed: int = 7) -> List[str]:
    r = random.Random(seed)
    out: List[str] = []
    T = []
    # ---- banking / UPI / OTP ------------------------------------------------------------------
    T += [lambda: f"Rs {_amt(r)} debited from A/c XX{_last4(r)} on {_date(r)} to VPA {r.choice(NAMES).lower()}@{r.choice(['okhdfcbank','oksbi','ybl','paytm','okaxis'])}. UPI Ref {_ref(r)}. Not you? Call {r.choice([1800, 1860])}{_n(r,100000,999999)}",
          lambda: f"{r.choice(BANKS)}: Rs.{_amt(r)} credited to your a/c XXXX{_last4(r)} on {_date(r)} by UPI/{_ref(r)}. Avl Bal Rs.{_amt(r)}",
          lambda: f"Dear Customer, INR {_amt(r)} was spent on your {r.choice(BANKS)} Credit Card ending {_last4(r)} at {r.choice(MERCH).upper()} on {_date(r)}. Avl limit INR {_amt(r)}. Not you? Block card via app.",
          lambda: f"{_ref(r,6)} is your OTP for transaction of Rs {_amt(r)} at {r.choice(MERCH)}. Valid for {r.choice([3,5,10])} minutes. Do not share this OTP with anyone. -{r.choice(BANKS)}",
          lambda: f"OTP for login to {r.choice(BANKS)} NetBanking is {_ref(r,6)}. Never share your OTP, PIN or password with anyone including bank staff.",
          lambda: f"Your {r.choice(MERCH)} verification code is {_ref(r,6)}. It expires in {r.choice([5,10,15])} minutes. Don't share it with anyone.",
          lambda: f"Use {_ref(r,6)} as your one-time password to sign in. {r.choice(MERCH)} will never call you to ask for this code.",
          lambda: f"Your {r.choice(BANKS)} statement for card XX{_last4(r)} is generated. Total due Rs {_amt(r)}, minimum due Rs {_amt(r)}, due date {_date(r)}. Pay via the mobile app or net banking.",
          lambda: f"Reminder: EMI of Rs {_amt(r)} for loan A/c XX{_last4(r)} will be auto-debited on {_date(r)}. Please keep sufficient balance. -{r.choice(BANKS)}",
          lambda: f"Payment of Rs {_amt(r)} received from {r.choice(NAMES)} via UPI. Ref no {_ref(r)}. Balance Rs {_amt(r)}. -{r.choice(['Paytm','PhonePe','Google Pay'])}",
          lambda: f"Your cheque no {_ref(r,6)} for Rs {_amt(r)} has been cleared on {_date(r)}. Thank you for banking with {r.choice(BANKS)}.",
          lambda: f"Rs {_amt(r)} withdrawn from ATM on {_date(r)} {_time(r)} using card XX{_last4(r)}. Avl bal Rs {_amt(r)}. If not done by you, call the number on your card.",
          lambda: f"Dear {r.choice(NAMES)}, your {r.choice(BANKS)} FD of Rs {_amt(r)} matures on {_date(r)}. Visit your branch or use the mobile app to renew. T&C apply.",
          lambda: f"Update: your KYC is due. Please visit your nearest branch with originals of your ID or update through the official {r.choice(BANKS)} mobile app. No link will be sent by SMS.",
          lambda: f"{r.choice(BANKS)} never asks for your PIN, OTP or CVV on call, SMS or email. Stay alert to fraud. Report suspicious activity at https://www.{SITES.get('HDFC Bank')}/fraud-help",
          lambda: f"Your UPI PIN was changed successfully on {_date(r)}. If you did not do this, contact your bank immediately through the official app.",
          lambda: f"Mandate for Rs {_amt(r)} to {r.choice(MERCH)} created on UPI AutoPay. Next debit on {_date(r)}. Manage in your UPI app.",
          lambda: f"FASTag balance low: Rs {_amt(r)} for vehicle TN{_n(r,10,99)}XX{_n(r,1000,9999)}. Recharge via your issuing bank app. -{r.choice(BANKS)}",
          ]
    # ---- telecom ------------------------------------------------------------------------------
    T += [lambda: f"Recharge of Rs {r.choice([199,239,299,349,479,666,719])} successful on {_date(r)}. Validity {r.choice([28,56,84])} days, {r.choice([1.5,2,3])}GB/day. -{r.choice(TELCOS)}",
          lambda: f"You have used 80% of your daily data quota. Balance {r.choice([300,500])}MB valid till midnight. Dial *121# or use the {r.choice(TELCOS)} app to top up.",
          lambda: f"Your {r.choice(TELCOS)} postpaid bill of Rs {_amt(r)} is generated, due {_date(r)}. Pay from the app or at the nearest store. Ignore if already paid.",
          lambda: f"Welcome to {r.choice(['Dubai','Singapore','Bangkok','London'])}! International roaming pack is active. Calls from Rs 2/min. -{r.choice(TELCOS)}",
          lambda: f"Missed call alert: {_ref(r,10)} called you at {_time(r)}. -{r.choice(TELCOS)}",
          lambda: f"Your SIM port request has been accepted. Your number will switch to the new operator on {_date(r)} by {_time(r)}. Reply CANCEL to stop.",
          ]
    # ---- e-commerce / delivery ----------------------------------------------------------------
    T += [lambda: f"Your {r.choice(MERCH)} order #{_ref(r,9)} has been shipped and will arrive by {_date(r)}. Track in the app. Thank you for shopping!",
          lambda: f"Out for delivery: your package from {r.choice(MERCH)} is arriving today with {r.choice(COURIERS)}. Delivery OTP: {_ref(r,4)}. Share the OTP only with the delivery partner at your door.",
          lambda: f"{r.choice(COURIERS)}: AWB {_ref(r,11)} delivered on {_date(r)} {_time(r)}. Hope you liked it! Rate us in the app.",
          lambda: f"Your order of {r.choice(['groceries','a phone case','2 items','a book'])} worth Rs {_amt(r)} is confirmed. Estimated delivery in {r.choice([10,15,30,45])} minutes. -{r.choice(MERCH)}",
          lambda: f"Refund of Rs {_amt(r)} for your cancelled order has been initiated to the original payment method. It will reflect in {r.choice([3,5,7])} working days. -{r.choice(MERCH)}",
          lambda: f"Hi {r.choice(NAMES)}, your cab is arriving in {r.choice([2,3,5])} mins. Driver {r.choice(NAMES)}, TN{_n(r,10,99)} AB {_n(r,1000,9999)}. Share OTP {_ref(r,4)} to start the ride.",
          lambda: f"Dear customer, your return request for order #{_ref(r,9)} is approved. Pickup scheduled on {_date(r)}. Details at https://www.{r.choice(['amazon.in','flipkart.com','myntra.com'])}/orders",
          lambda: f"Get 20% off on your next order! Use code {r.choice(['SAVE20','WELCOME','DIWALI','FEST25'])}. Valid till {_date(r)}. T&C apply. -{r.choice(MERCH)}",
          lambda: f"Your subscription to {r.choice(['Netflix','Hotstar','Prime','Spotify','YouTube Premium'])} renews on {_date(r)} for Rs {_amt(r)}. Manage your plan in account settings.",
          ]
    # ---- travel -------------------------------------------------------------------------------
    T += [lambda: f"PNR {_ref(r,10)}: train {_n(r,10000,22999)} {r.choice(CITIES)} to {r.choice(CITIES)} on {_date(r)}. Coach S{_n(r,1,9)} berth {_n(r,1,72)}. Status CNF. Happy journey! -IRCTC",
          lambda: f"Booking confirmed. Flight {r.choice(['6E','AI','UK','SG'])}{_n(r,100,999)} {r.choice(CITIES)}-{r.choice(CITIES)} on {_date(r)} at {_time(r)}. Web check-in opens 48 hrs before departure.",
          lambda: f"Your bus ticket {_ref(r,8)} {r.choice(CITIES)} to {r.choice(CITIES)} on {_date(r)} boarding {_time(r)}. Seat {_n(r,1,40)}. -RedBus",
          lambda: f"Metro card balance Rs {_n(r,5,500)}. Recharge at any station or via the metro app. Have a safe ride.",
          ]
    # ---- utilities / civic --------------------------------------------------------------------
    T += [lambda: f"Your electricity bill for consumer no {_ref(r,10)} is Rs {_amt(r)}, due {_date(r)}. Pay on the official board website or app. Ignore if paid.",
          lambda: f"LPG cylinder booked. Delivery expected on {_date(r)}. Delivery code {_ref(r,4)}. Please give the code only to the delivery person. -Indane",
          lambda: f"Water supply will be interrupted in {r.choice(['Anna Nagar','Gandhipuram','Andheri','Koramangala'])} on {_date(r)} from {_time(r)} for maintenance work. Please store water. -Municipal Corporation",
          lambda: f"Your passbook has been updated. Latest EPF balance as on {_date(r)} is Rs {_amt(r)}. Check on the UMANG app or the EPFO member portal. -EPFO",
          lambda: f"Your Aadhaar update request is received. URN {_ref(r,14)}. Track status at https://myaadhaar.uidai.gov.in. -UIDAI",
          lambda: f"Income Tax: your return for AY 2025-26 has been processed. Intimation sent to your registered email. Visit https://www.incometax.gov.in to view.",
          lambda: f"Vaccination reminder: your child's next dose is due on {_date(r)} at {r.choice(['PHC','City Hospital','Apollo Clinic'])}. Please carry the immunisation card.",
          ]
    # ---- school / work / appointments ---------------------------------------------------------
    T += [lambda: f"Dear Parent, school will remain closed on {_date(r)} due to local holiday. Classes resume {_date(r)}. -Principal",
          lambda: f"Reminder: your appointment with Dr. {r.choice(NAMES)} is on {_date(r)} at {_time(r)} at {r.choice(['Apollo Clinic','Fortis Hospital','City Dental Care'])}. Reply 1 to confirm, 2 to reschedule.",
          lambda: f"Your lab report is ready. Collect it from the centre or download from the official app using your registered mobile number. -{r.choice(['Dr Lal PathLabs','Thyrocare','Metropolis'])}",
          lambda: f"Fee receipt: Rs {_amt(r)} received towards semester fees on {_date(r)}. Receipt no {_ref(r,6)}. -Accounts Office",
          lambda: f"Hall ticket for the {r.choice(['semester','internal','practical'])} examination is available on the college portal. Exams begin {_date(r)}. -Controller of Examinations",
          lambda: f"Team meeting moved to {_time(r)} tomorrow. Please join from the usual link. - {r.choice(NAMES)}",
          lambda: f"Interview scheduled for {_date(r)} at {_time(r)} for the {r.choice(['software engineer','analyst','intern'])} role. Please carry your resume and ID. -HR team",
          ]
    # ---- Hinglish / casual chat ---------------------------------------------------------------
    chat = ["bhai kal shaam ko milte hain, cricket khelne chalna hai", "mummy ne bola dinner pe ghar aa jao", "ok done, I'll send the notes tonight", "are you coming to college tomorrow? lab record submission hai",
            "happy birthday da! party kab de raha hai", "reached home safely, call you later", "can you share the assignment pdf? mine did not open", "paneer butter masala bana hai, aaja",
            "traffic is crazy today, will be 20 mins late", "thanks bro, will transfer the money tomorrow morning", "movie at 7? i'll book tickets", "anna, appa is asking when you will come home for pongal",
            "did you finish the ml project report? sir is asking for the draft", "lunch kar liya? office se nikal raha hu", "pls send me the hostel fee receipt photo", "good morning! have a great day",
            "meeting ke baad call karta hu", "nalla irukka? call me when free", "recharge kara diya maine, check kar le", "mausi ki shaadi ka invitation bheja hai whatsapp pe dekh lena"]
    T += [lambda: r.choice(chat)]
    # ---- official-link promos / alerts (legit URLs to real brand domains) ----------------------
    T += [lambda: f"{r.choice(MERCH)}: Your cart has items waiting. Complete your order at https://www.{r.choice(['amazon.in','flipkart.com','swiggy.com','zomato.com','myntra.com'])}/cart",
          lambda: f"Download the official {r.choice(BANKS)} app from the Google Play Store or Apple App Store only. Never install apps from links sent by strangers.",
          lambda: f"Your {r.choice(MERCH)} invoice for order {_ref(r,9)} is available at https://www.{r.choice(['amazon.in','flipkart.com','bigbasket.com'])}/invoice/{_ref(r,8)}",
          lambda: f"Security alert: new login to your Google account from {r.choice(['Chennai','Mumbai','Delhi'])}. If this was you, no action needed. Otherwise review at https://myaccount.google.com/security",
          ]

    # ---- second family: different sentence structure / register (bank, gov, health, edtech, fintech) ---------------
    T2 = [lambda: f"Alert: INR {_amt(r)} has been {r.choice(['debited','credited'])} {r.choice(['to','from'])} your {r.choice(BANKS)} account ending {_last4(r)} on {_date(r)}. Current balance INR {_amt(r)}.",
          lambda: f"Thank you for using your {r.choice(BANKS)} Debit Card ending {_last4(r)} for a purchase of INR {_amt(r)} at {r.choice(MERCH)}. Transaction successful.",
          lambda: f"{_ref(r,6)} is the OTP to authorise your payment of Rs {_amt(r)} to {r.choice(MERCH)}. Please do not disclose it to anyone. -{r.choice(BANKS)}",
          lambda: f"Your verification code is {_ref(r,6)}. Do not share this code with anyone. If you did not request it, please ignore this message.",
          lambda: f"One Time Password {_ref(r,6)} for login. Valid for {r.choice([2,3,5,10])} min. Never share OTP with anyone, we never ask for it.",
          lambda: f"Dear Customer, your {r.choice(['recharge','bill payment','insurance premium','loan EMI'])} of Rs.{_amt(r)} was received on {_date(r)}. Reference {_ref(r,10)}. Thank you.",
          lambda: f"Your request {_ref(r,8)} has been registered. We will update you within {r.choice([2,3,5,7])} working days. Track it using the official app. -{r.choice(BANKS)}",
          lambda: f"Dear {r.choice(NAMES)}, your cheque book request is processed and will be delivered to your registered address in {r.choice([5,7,10])} days.",
          lambda: f"Hi {r.choice(NAMES)}, your parcel is out for delivery today. Our agent will call before arriving. Please keep the delivery OTP {_ref(r,4)} ready and share it only with the agent at your door.",
          lambda: f"Dear {r.choice(NAMES)}, {r.choice(COURIERS)} shipment {_ref(r,10)} is scheduled for delivery on {_date(r)}. Track at https://www.{r.choice(['delhivery.com','bluedart.com','dtdc.in','ecomexpress.in'])}/track",
          lambda: f"Your Aadhaar enrolment is complete. Enrolment ID {_ref(r,14)}. Check status at https://uidai.gov.in. Regards, UIDAI",
          lambda: f"CoWIN: Dear {r.choice(NAMES)}, vaccination certificate generated. Download from https://www.cowin.gov.in using your registered mobile.",
          lambda: f"Dear Taxpayer, your GST return for {r.choice(['Oct','Nov','Sep'])} is due on {_date(r)}. File on the GST portal to avoid late fee. -GSTN",
          lambda: f"Your electricity meter reading for the month is {_n(r,100,900)} units. Bill amount Rs {_amt(r)} due {_date(r)}. Pay on the official website or app.",
          lambda: f"Gas booking successful. Booking number {_ref(r,8)}. You will receive the cylinder in 2-3 days. Pay on delivery or online via the official app.",
          lambda: f"IMPORTANT: Fraudsters pretend to be bank officials. {r.choice(BANKS)} will never ask you to share OTP, PIN, CVV or install any app. Report fraud on 1930 or at cybercrime.gov.in.",
          lambda: f"Safety tip from {r.choice(BANKS)}: do not click on links in SMS from unknown senders. Always type the official website address yourself.",
          lambda: f"Dear Customer, as per RBI guidelines periodic KYC update is due for account ending {_last4(r)}. Please submit your documents at any branch or through the official mobile banking app. Please ignore if already done.",
          lambda: f"Dear Customer, your {r.choice(BANKS)} Credit Card bill of Rs {_amt(r)} is due on {_date(r)}. Pay using NetBanking, the mobile app or UPI. Late payment may attract charges.",
          lambda: f"Your Google Pay payment of Rs {_amt(r)} to {r.choice(NAMES)} was successful. UPI transaction ID {_ref(r,12)}.",
          lambda: f"Hi {r.choice(NAMES)}, your {r.choice(['Swiggy','Zomato','BigBasket','Blinkit'])} order has been delivered. We hope you enjoyed it. Rate your experience in the app.",
          lambda: f"Your {r.choice(['course','test','assignment','webinar'])} on {r.choice(['Python','Data Structures','Machine Learning','Excel'])} starts on {_date(r)}. Join using the link in your registered email.",
          lambda: f"Dear Student, your admit card for the {r.choice(['NPTEL','university','entrance'])} exam is available on the official website. Exam date {_date(r)}.",
          lambda: f"Your seat for {r.choice(['Pushpa 2','Leo','Jawan','RRR','Kalki'])} at {r.choice(['PVR','INOX','Cinepolis'])} {r.choice(CITIES)} is confirmed. Show booking ID {_ref(r,8)} at the cinema.",
          lambda: f"Hi {r.choice(NAMES)}, thanks for visiting {r.choice(['Reliance Trends','Lifestyle','Max Fashion','Pantaloons'])}. Your bill of Rs {_amt(r)} is paid. Feedback: reply 1 to 5.",
          lambda: f"{r.choice(NAMES)} sent you Rs {_amt(r)} on {r.choice(['PhonePe','Paytm','Google Pay'])}. Money has been credited to your bank account.",
          lambda: f"Dear Customer, your {r.choice(['broadband','DTH','FASTag','postpaid'])} plan will renew automatically on {_date(r)}. Manage your plan in the official app.",
          lambda: f"Reminder from {r.choice(['Apollo','Fortis','Manipal','Max'])} Hospital: your follow-up consultation is on {_date(r)} at {_time(r)}. Please bring previous reports.",
          lambda: f"Your complaint {_ref(r,7)} has been closed. If you are not satisfied, you may reopen it within 7 days through the official helpline.",
          lambda: f"Congratulations {r.choice(NAMES)}! You have been shortlisted for the {r.choice(['internship','campus placement','scholarship interview'])}. Details have been sent to your registered email.",
          lambda: f"Welcome to {r.choice(BANKS)}! Your new savings account is now active. Your customer ID is {_ref(r,9)}. Download the official mobile app to get started.",
          lambda: f"Your {r.choice(MERCH)} wallet has been credited with Rs {_n(r,10,500)} cashback for your recent order. Use it on your next purchase.",
          lambda: f"Thank you for your payment of Rs {_amt(r)}. Your receipt number is {_ref(r,8)}. -{r.choice(['Municipal Corporation','Water Board','Electricity Board','Gas Agency'])}",
          lambda: f"Dear Customer, a new login to your {r.choice(BANKS)} NetBanking was detected on {_date(r)} at {_time(r)}. If this was you, no action is needed.",
          lambda: f"{r.choice(NAMES)}, don't forget the group study at 5 pm tomorrow. Bring your laptop and the notes.",
          lambda: f"Anna, I sent you the money, check GPay. Also call amma, she is asking about the function.",
          ]
    T += T2 + T2
    for _ in range(n):
        out.append(r.choice(T)())
    return out
