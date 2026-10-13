from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from .extensions import db
from .forms import DeleteForm, NoteForm
from .models import Note
from .security import audit

bp = Blueprint("notes", __name__)


def _get_own_note(note_id: int) -> Note:
    """A01 Broken Access Control: every lookup is scoped to the current user.

    Another user's note returns 404 (not 403), so IDs can't be probed to learn
    which notes exist.
    """
    note = db.session.execute(
        db.select(Note).filter_by(id=note_id, owner_id=current_user.id)
    ).scalar_one_or_none()
    if note is None:
        if db.session.get(Note, note_id) is not None:
            audit("idor_attempt", note_id=note_id)
        abort(404)
    return note


@bp.route("/")
@login_required
def index():
    notes = db.session.execute(
        db.select(Note).filter_by(owner_id=current_user.id).order_by(Note.updated_at.desc())
    ).scalars().all()
    return render_template("notes/index.html", notes=notes, delete_form=DeleteForm())


@bp.route("/notes/new", methods=["GET", "POST"])
@login_required
def create():
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(owner_id=current_user.id, title=form.title.data.strip(), body=form.body.data or "")
        db.session.add(note)
        db.session.commit()
        flash("Note saved.", "success")
        return redirect(url_for("notes.view", note_id=note.id))
    return render_template("notes/form.html", form=form, heading="New note")


@bp.route("/notes/<int:note_id>")
@login_required
def view(note_id: int):
    return render_template("notes/view.html", note=_get_own_note(note_id), delete_form=DeleteForm())


@bp.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit(note_id: int):
    note = _get_own_note(note_id)
    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data.strip()
        note.body = form.body.data or ""
        db.session.commit()
        flash("Note updated.", "success")
        return redirect(url_for("notes.view", note_id=note.id))
    return render_template("notes/form.html", form=form, heading="Edit note")


@bp.route("/notes/<int:note_id>/delete", methods=["POST"])  # state changes are never GET
@login_required
def delete(note_id: int):
    note = _get_own_note(note_id)
    if DeleteForm().validate_on_submit():
        db.session.delete(note)
        db.session.commit()
        flash("Note deleted.", "success")
    return redirect(url_for("notes.index"))
