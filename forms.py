"""Formulaires WTForms.

Chaque FlaskForm inclut un champ caché csrf_token : le serveur refuse
tout POST qui n'a pas le bon jeton (protection CSRF).
"""
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp


class RegisterForm(FlaskForm):
    username = StringField("Nom d'utilisateur", validators=[
        DataRequired(),
        Length(min=3, max=32),
        # Liste blanche : on n'accepte que ce qu'on connaît
        Regexp(r"^[A-Za-z0-9_.-]+$",
               message="Lettres, chiffres, _ . - uniquement."),
    ])
    password = PasswordField("Mot de passe", validators=[
        DataRequired(),
        # La longueur est le facteur le plus important (recommandation NIST)
        Length(min=12, max=128, message="Entre 12 et 128 caractères."),
    ])
    confirm = PasswordField("Confirmer le mot de passe", validators=[
        DataRequired(),
        EqualTo("password", message="Les mots de passe ne correspondent pas."),
    ])


class LoginForm(FlaskForm):
    username = StringField("Nom d'utilisateur",
                           validators=[DataRequired(), Length(max=32)])
    password = PasswordField("Mot de passe",
                             validators=[DataRequired(), Length(max=128)])


class NoteForm(FlaskForm):
    title = StringField("Titre", validators=[DataRequired(), Length(max=200)])
    body = TextAreaField("Contenu", validators=[DataRequired(), Length(max=20000)])


class TotpForm(FlaskForm):
    # 6 chiffres (TOTP) ou un code de secours du type ABCDE-FGHIJ
    code = StringField("Code", validators=[DataRequired(), Length(min=6, max=20)])


class DisableTotpForm(FlaskForm):
    # Désactiver la 2FA est sensible : on redemande mot de passe ET code
    password = PasswordField("Mot de passe",
                             validators=[DataRequired(), Length(max=128)])
    code = StringField("Code 2FA ou code de secours",
                       validators=[DataRequired(), Length(min=6, max=20)])


class ChangePasswordForm(FlaskForm):
    # On redemande l'ancien mot de passe : un voleur de cookie ne le connaît pas
    current = PasswordField("Mot de passe actuel",
                            validators=[DataRequired(), Length(max=128)])
    new = PasswordField("Nouveau mot de passe", validators=[
        DataRequired(),
        Length(min=12, max=128, message="Entre 12 et 128 caractères."),
    ])
    confirm = PasswordField("Confirmer le nouveau mot de passe", validators=[
        DataRequired(),
        EqualTo("new", message="Les mots de passe ne correspondent pas."),
    ])


class EmptyForm(FlaskForm):
    """Formulaire sans champ, juste pour le jeton CSRF (supprimer, déconnexion)."""
