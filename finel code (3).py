import datetime

#  Rules aur Weights  are defined (At which event hoe much risk score will be incresed)
RISK_RULES = {
    "failed_login": 25,
    "password_change": 10,
    "suspicious_ip": 40,
    "api_rate_limit_exceeded": 30
}

#  Database at place of temporary memory (Dictionary) we are using 
user_database = {}

#  Core Logic: To calculate the risk score
def process_monitoring_event(event):
    user_id = event["user_id"]
    action = event["action"]
    
    # Check if this action is in our rule or not
    if action in RISK_RULES:
        points_to_add = RISK_RULES[action]
    else:
        points_to_add = 0 # if there is any unknown events then 0 points
        
    # If the user vusuted first time initialize its record
    if user_id not in user_database:
        user_database[user_id] = {
            "current_risk_score": 0,
            "status": "Low",
            "history": []
        }
    
    # Increase risk score
    user_database[user_id]["current_risk_score"] += points_to_add
    
    # Cap the risk score at 100 (Risk score do not exceeds 100)
    if user_database[user_id]["current_risk_score"] > 100:
        user_database[user_id]["current_risk_score"] = 100
        
    #  update status (Low, Medium, High, Critical)
    score = user_database[user_id]["current_risk_score"]
    if score >= 75:
        user_database[user_id]["status"] = "Critical"
    elif score >= 40:
        user_database[user_id]["status"] = "High"
    elif score >= 20:
        user_database[user_id]["status"] = "Medium"
    else:
        user_database[user_id]["status"] = "Low"
        
    # Save the event into history 
    user_database[user_id]["history"].append(event)

# 4. GET to work like API (to see users status)
def get_user_risk_profile(user_id):
    if user_id in user_database:
        return user_database[user_id]
    else:
        return "User not found!"

# --- DEMO (Lets run the code) ---

# First event: User has put on wrong password
event1 = {
    "user_id": "user_abc",
    "action": "failed_login",
    "timestamp": str(datetime.datetime.now())
}
process_monitoring_event(event1)

# Second event: User again put on the wrong password and API is also suspicious
event2 = {
    "user_id": "user_abc",
    "action": "suspicious_ip",
    "timestamp": str(datetime.datetime.now())
}
process_monitoring_event(event2)

# To check what is the users current Status
print("--- User Risk Profile Summary ---")
profile = get_user_risk_profile("user_abc")
print(f"User ID: user_abc")
print(f"Total Risk Score: {profile['current_risk_score']}")
print(f"Risk Status: {profile['status']}")
print(f"Total Events Tracked: {len(profile['history'])}")