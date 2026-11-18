"""Submissions WTForms."""
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, Optional, URL


class SubmissionForm(FlaskForm):
    name = StringField(
        "Model / Project Name",
        validators=[DataRequired(), Length(min=2, max=128)],
        render_kw={"placeholder": "e.g. MyTextClassifier v2"},
    )
    description = TextAreaField(
        "Description",
        validators=[Optional(), Length(max=2000)],
        render_kw={"placeholder": "What does the model do? Who is the intended user?", "rows": 4},
    )
    repo_url = StringField(
        "GitHub Repository URL",
        validators=[Optional(), URL(message="Must be a valid URL")],
        render_kw={"placeholder": "https://github.com/owner/repo"},
    )
    model_type = SelectField(
        "Model Type",
        choices=[
            ("", "— Select type —"),
            ("classification", "Classification"),
            ("regression", "Regression"),
            ("nlp", "NLP / Text"),
            ("computer_vision", "Computer Vision"),
            ("recommendation", "Recommendation"),
            ("generative", "Generative AI"),
            ("other", "Other"),
        ],
        validators=[Optional()],
    )
    framework = SelectField(
        "Framework",
        choices=[
            ("", "— Select framework —"),
            ("pytorch", "PyTorch"),
            ("tensorflow", "TensorFlow / Keras"),
            ("sklearn", "scikit-learn"),
            ("jax", "JAX"),
            ("huggingface", "HuggingFace Transformers"),
            ("onnx", "ONNX"),
            ("other", "Other"),
        ],
        validators=[Optional()],
    )
    submit = SubmitField("Submit for Scan")
