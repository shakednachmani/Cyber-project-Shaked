from views import homepage,add_client,client_details

from authentication import register, login, logout,change_password,forgot_password,reset_password,enter_token


def configure_routes(app):
    app.add_url_rule('/', 'login', login)
    app.add_url_rule('/home', 'homepage', homepage)
    app.add_url_rule('/register', 'register', register,methods=["POST", "GET"])
    app.add_url_rule('/login', 'login', login,methods=["POST", "GET"])
    app.add_url_rule('/logout', 'logout', logout,methods=[ "POST","GET"])
    app.add_url_rule('/change_password', 'ChangePassword', change_password,methods=[ "POST","GET"])
    app.add_url_rule('/forget_password', 'forget_password', forgot_password,methods=[ "POST","GET"])
    app.add_url_rule('/reset_password', 'reset_password', reset_password,methods=[ "POST","GET"])
    app.add_url_rule('/reset_password/<token>', 'reset_password', reset_password, methods=["POST", "GET"])
    app.add_url_rule('/enter_token', 'enter_token',enter_token, methods=['GET', 'POST'])
    app.add_url_rule('/add-client', 'add_client', add_client,methods=[ "POST"])
    app.add_url_rule('/client/<username>', 'client_details', client_details, methods=["GET"])



    
    
