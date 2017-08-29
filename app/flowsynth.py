from flask import Blueprint, render_template, request, Response, redirect

# setup the flowsynth blueprint
flowsynth_blueprint = Blueprint('flowsynth_blueprint', __name__, template_folder='templates/')

@flowsynth_blueprint.route('/flowsynth/index.html', methods=['GET', 'POST'])
def index_redirect():
    return redirect('/flowsynth/')

@flowsynth_blueprint.route("/flowsynth/")
@flowsynth_blueprint.route("/flowsynth")
def page_index():
    return "FLOWSYTH ... coming soon."
#    return render_template('/flowsynth/index.html', page='')
