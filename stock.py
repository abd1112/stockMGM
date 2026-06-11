from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import json
import xlsxwriter
import os, io
from functools import wraps
import datetime


app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # change this in production!
# -------------------------------------- my files -------------------------------------------
USERS_FILE = "users.json"
INVENTORY_FILE = "inventory.json"
DEPARTMENT = "department.json"
HISTORY = "history.json"
UPDATES = "update_history.json"
# -------------------------------------- my variables ---------------------------------------
time_format = "%d/%m/%Y"
# -------------------------------------- my functions ---------------------------------------
# --------------------- load users function -------------------------
def load_users():
    if not os.path.exists(USERS_FILE):
        return {"users": []}
    with open(USERS_FILE, "r") as f:
        return json.load(f)
# -------------------- save users ------------------------------
def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)
# ---------------------- find users ----------------------------
def find_user(username):
    data = load_users()
    for user in data.get("users", []):
        if user["username"] == username:
            return user
    return None
# ------------------ load inventory -------------------
def load_inventory():
    if not os.path.exists(INVENTORY_FILE):
        return {"categories": []}
    with open(INVENTORY_FILE, "r") as f:
        return json.load(f)
# ------------------ load departments -------------------
def load_dep():
    if not os.path.exists(DEPARTMENT):
        return {}
    with open(DEPARTMENT, "r") as f:
        return json.load(f)
# ------------------ load history -------------------
def load_history():
    if not os.path.exists(HISTORY):
        return {}
    with open(HISTORY, "r") as f:
        return json.load(f)
# ------------------ load updates history -------------------    
def load_updates():
    if not os.path.exists(UPDATES):
        return {}
    with open(UPDATES, "r") as f:
        return json.load(f)
# ------------------ save departments -------------------
def save_dep(data):
    with open(DEPARTMENT, "w") as f:
        json.dump(data, f, indent=2)
# ------------------ save inventory -------------------
def save_inventory(data):
    with open(INVENTORY_FILE, "w") as f:
        json.dump(data, f, indent=2)
# ------------------ save history -------------------
def save_history(data):
    with open(HISTORY, "w") as f:
        json.dump(data, f, indent=2)
# ------------------ save updates history -------------------
def save_updates(data):
    with open(UPDATES, "w") as f:
        json.dump(data, f, indent=2)
# ------------------ export_history_to_excel -------------------
def export_history_to_excel(history_list):
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {'in_memory': True})
    worksheet = workbook.add_worksheet("Operations")

    # Write headers
    headers = ["Op ID", "Date", "Department", "Item", "Model", "Quantity"]
    for col_num, header in enumerate(headers):
        worksheet.write(0, col_num, header)

    # Write data rows
    for row_num, op in enumerate(history_list, start=1):
        worksheet.write(row_num, 0, op.get("operation_id", ""))
        worksheet.write(row_num, 1, op.get("date", ""))
        worksheet.write(row_num, 2, op.get("department", ""))
        worksheet.write(row_num, 3, op.get("item", ""))
        worksheet.write(row_num, 4, op.get("model", ""))
        worksheet.write(row_num, 5, op.get("quantity", ""))

    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="operations_report.xlsx")
# ------------------ get_next_cat_id -------------------
def get_next_cat_id(categories):
    if not categories:
        return 1
    max_id = max(cat.get("id", 0) for cat in categories)
    return max_id + 100
# ------------------ get_next_cat_id -------------------
def get_next_mod_id(cat_id,mods):
    id_list = []
    if not mods:
        return cat_id + 1
    for model in mods:
        id_list.append(model["id"])
    max_id = int(max(id_list))
    #max_id = max(model.get("id",0) for model in mods)
    return int(max_id + 1)
# ------------------ find category -------------------
def find_category(inventory, cat_id):
    for cat in inventory.get("categories", []):
        if cat["id"] == cat_id:
            return cat
    return None
# ------------------ find model -------------------
def find_model(category, model_id):
    for mod in category.get("models", []):
        if int(mod["id"]) == int(model_id):
            return mod
    return None
# ------------------ get operation id -------------------
def get_op_id(model_id,cat_id):
    current_time = datetime.datetime.now()
    minutes = str(current_time.minute)
    hours = str(current_time.hour)
    op_id = f"{minutes[0:2]}{hours[0:2]}{model_id}"
    return op_id
# ------------------ if_dep_exist -------------------
def if_dep_exist(name):
    data = load_dep()
    check = False
    for department in data["departments"]:
        if department["name"] == name:
            check = True
            break
    return check
# ------------------ get current time -------------------
def get_current_time():
    current_time = datetime.datetime.now()
    today_date = f"{current_time.day}-{current_time.month}-{current_time.year}"
    return today_date
# ------------------ login_required function -------------------
# Define login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("You must log in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function
# --------------------------------------- @app.route function ------------------------------------
# ------------------ home function -------------------
@app.route("/")
@app.route("/home")
def home():
    # if user is logged in, show a welcome message
    username = session.get("username")
    return render_template("home.html", title="Home Page", username=username)

# ------------------ register function -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if find_user(username):
            flash("Username already exists. Choose another.", "error")
            return render_template("register.html")

        # hash the password
        pw_hash = generate_password_hash(password)
        data = load_users()
        data["users"].append({
            "username": username,
            "password_hash": pw_hash
        })
        save_users(data)
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Register")

# ------------------ login function -------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        user = find_user(username)
        if user and check_password_hash(user["password_hash"], password):
            # login success
            session["username"] = username
            flash("Logged in successfully.", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials.", "error")
            return render_template("login.html")

    return render_template("login.html", title="Login")

# ------------------ logout function -------------------
@app.route("/logout")
def logout():
    session.pop("username", None)  # remove username from session if present
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ------------------ inventory function (login required) -------------------
@app.route("/inventory", methods=["Get"])
@login_required
def inventory():
    inv = load_inventory()
    return render_template("inventory.html",title="Inventory", inventory=inv)
# ------------------ delete model (login required) -------------------
@app.route("/delete_model/<int:cat_id>/<model_id>", methods=["POST"])
def delete_model(cat_id, model_id):
    inv = load_inventory()
    found = False

    for cat in inv.get("categories", []):
        # in your data `id` is an integer or string? Here you gave them as numbers 100, 200 etc
        # so cat["id"] is an integer if JSON parser preserves it.
        if cat.get("id") == cat_id:
            new_models = []
            for mod in cat.get("models", []):
                # mod["id"] in JSON is a string "101", "102", etc in your data
                if str(mod.get("id")) == str(model_id):
                    found = True
                    # skip this model, i.e. delete it
                else:
                    new_models.append(mod)
            cat["models"] = new_models
            break

    if found:
        flash(f"Model {model_id} in category {cat_id} deleted.", "success")
    else:
        flash(f"Model {model_id} not found in category {cat_id}.", "error")

    save_inventory(inv)
    return redirect(url_for("inventory"))
# ------------------ add category function (login required) -------------------
@app.route("/inventory/add_category", methods=["GET", "POST"])
@login_required
def add_category():
    if request.method == "POST":
        name = request.form.get("name").strip()
        if not name:
            flash("Category name is required.", "error")
            return render_template("add_category.html")
        inv = load_inventory()
        # check duplicate by name
        for c in inv["categories"]:
            if c["name"].lower() == name.lower():
                flash("Category already exists.", "error")
                return render_template("add_category.html")
        new_id = get_next_cat_id(inv["categories"])
        inv["categories"].append({
            "id": new_id,
            "name": name,
            "models": []
        })
        save_inventory(inv)
        flash(f"Category '{name}' added.", "success")
        return redirect(url_for("inventory"))
    return render_template("add_category.html", title="Add Category")

# ------------------ add model function (login required) -------------------
@app.route("/inventory/add_model/<int:cat_id>", methods=["GET", "POST"])
@login_required
def add_model(cat_id):
    inv = load_inventory()
    category = find_category(inv, cat_id)
    
    if not category:
        flash("Category not found.", "error")
        return redirect(url_for("inventory"))

    model_id = int(get_next_mod_id(cat_id, category["models"]))

    if request.method == "POST":
        model_name = request.form.get("model").strip()
        manufacture = request.form.get("manufacture").strip()
        quantity = request.form.get("quantity")
        # validate
        if not model_id or not model_name or not quantity:
            flash("ID, model name, and quantity are required.", "error")
            return render_template("add_model.html", category=category)
        try:
            quantity = int(quantity)
        except ValueError:
            flash("Quantity must be an integer.", "error")
            return render_template("add_model.html", category=category)

        # check duplicate model id
        if find_model(category, model_id):
            flash("Model ID already exists in this category.", "error")
            return render_template("add_model.html", category=category)

        new_model = {
            "id": model_id,
            "model": model_name,
            "manufacture": manufacture,
            "quantity": quantity
        }
        category["models"].append(new_model)
        save_inventory(inv)
        flash(f"Model '{model_name}' added under category '{category['name']}'.", "success")
        return redirect(url_for("inventory"))

    return render_template("add_model.html",title="Add Model", category=category, mod_id=model_id)

# ------------------ update quantity function (login required) -------------------
@app.route("/inventory/update_quantity/<int:cat_id>/<model_id>", methods=["GET", "POST"])
@login_required
def update_quantity(cat_id, model_id):
    inv = load_inventory()
    updates = load_updates()
    category = find_category(inv, cat_id)
    if not category:
        flash("Category not found.", "error")
        return redirect(url_for("inventory"))
    model = find_model(category, model_id)
    if not model:
        flash("Model not found.", "error")
        return redirect(url_for("inventory"))

    if request.method == "POST":
        # get “change” which might be positive (increase) or negative (decrease)
        change = request.form.get("change")
        try:
            delta = int(change)
        except ValueError:
            flash("Invalid number for change.", "error")
            return render_template("update_quantity.html", category=category, model=model)

        new_qty = model["quantity"] + delta
        if new_qty < 0:
            flash("Resulting quantity cannot be negative.", "error")
            return render_template("update_quantity.html", category=category, model=model)

        model["quantity"] = new_qty
        if int(change) > 0:
            type="Entree"
        else:
            type="Sortie"
        new_update = {
                        "operation_id":get_op_id(model_id,cat_id),
                        "type":type,
                        "item":category["name"],
                        "model":model["model"],
                        "quantity":change,
                        "note":request.form.get("note"),
                        "date":get_current_time()
                    }
        updates.insert(0,new_update)
        save_updates(updates)
        save_inventory(inv)
        flash(f"Quantity updated. New quantity = {new_qty}.", "success")
        return redirect(url_for("inventory"))

    return render_template("update_quantity.html",title="Update Quantity", category=category, model=model)
# ------------------------------ give item to ----------------------
@app.route("/give_item_to/<int:cat_id>/<int:model_id>", methods=["GET", "POST"])
@login_required
def give_item_to(cat_id, model_id):
    inv = load_inventory()
    dep = load_dep()
    history = load_history()
    category = find_category(inv, cat_id)
    model = find_model(category, model_id)
    print(f"[DEBUG] give_item_to called with cat_id={cat_id}, model_id={model_id}")

    if request.method == "POST":
        department = request.form.get("department")
        item = category["name"]
        model_name = model["model"]
        qty = request.form.get("quantity")
        date = str(get_current_time())
        operation = {
            "date":date,
            "department":department,
            "item":item,
            "model":model_name,
            "quantity":qty,
            "operation_id":get_op_id(model_id,cat_id),
        }
        history.insert(0,operation)
        for category in inv["categories"]:
            if category["name"] == item:
                for mod in category["models"]:
                    if mod["model"] == model_name:
                        mod["quantity"] = mod["quantity"] - int(qty)
                        save_history(history)
                        save_inventory(inv)       
                        return redirect(url_for("inventory"))

    return render_template("give_item_to.html", title="Give an Item To",category=category, model=model, inventory=inv, departments=dep)

@app.route("/updates_history", methods=["GET", "POST"])
@login_required
def updates_history():
    updates = load_updates()
    inv = load_inventory()
    return render_template("updates_history.html", title="Updates History", updates=updates,inv=inv)
# ------------------------------ departments ----------------------
@app.route("/departments",methods=["GET", "POST"])
@login_required
def departments():
    dep = load_dep()
    history = load_history()
    for depart in dep["departments"]:
        depart["history"] = []
        for operation in history:
            if depart["name"] == operation["department"]:
                depart["history"].append(operation)
                save_dep(dep)
    
    return render_template("departments.html", title="Departments", departments=dep)
# ------------------------------ add departments ----------------------
@app.route("/add_department", methods=["GET", "POST"])
@login_required
def add_department():
    dep_list = load_dep() # this is a dict
    if request.method == "POST":
        new_dep = request.form.get("dep_name")
        if if_dep_exist(new_dep) == True:
            flash("This Department Name Already Exist", "Warning")
            return render_template("add_department.html", title="Add New Department")
        else:
            newDep = {
                "name":new_dep,
                "history":[]
            }
            dep_list["departments"].append(newDep)
            save_dep(dep_list)
            flash("Department Added Successfully", "Success")
            return redirect(url_for('departments'))
    return render_template("add_department.html", title="Add New Department")
# ------------------------------ operation history ----------------------
@app.route("/operation_history")
@login_required
def operation_history():
    history = load_history()
    dep      = load_dep()
    inv      = load_inventory()

    # read filters from query string
    dept_filter   = request.args.get("department", default="")
    item_filter   = request.args.get("item", default="")
    date_filter   = request.args.get("date_filter", default="")
    start_date    = request.args.get("start_date", default="")
    end_date      = request.args.get("end_date", default="")
    export_flag   = request.args.get("export", default="0")

    # apply filters
    filtered = []
    for op in history:
        ok = True
        if dept_filter and op["department"] != dept_filter:
            ok = False
        if item_filter and op["item"] != item_filter:
            ok = False
        # date filtering logic
        if date_filter == "custom" and start_date and end_date:
            # parse dates
            op_dt = datetime.strptime(op["date"], "%Y-%m-%d")  # adjust format
            sd    = datetime.strptime(start_date, "%Y-%m-%d")
            ed    = datetime.strptime(end_date, "%Y-%m-%d")
            if not (sd <= op_dt <= ed):
                ok = False
        elif date_filter == "last_month":
            # compute one month ago etc
            # ...
            pass
        elif date_filter == "last_year":
            # ...
            pass

        if ok:
            filtered.append(op)

    # If export requested, produce Excel file
    if export_flag == "1":
        return export_history_to_excel(filtered)

    # Else render page
    return render_template("operation_history.html",
                           history=filtered,
                           departments=dep,
                           inv=inv)
# ------------------------------ dashboard ----------------------
@app.route("/dashboard")
@login_required
def dashboard():
    inv = load_inventory()
    categories = inv.get("categories", [])
    return render_template("dashboard.html",title="Dashboard", username=session.get("username"), categories=categories)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
