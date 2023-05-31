from django import forms


CHOICES = (
    ("Patient", "Patient"),
    ("Auditor", "Auditor"),
    
)


class UserRegistrationForm(forms.Form):
    username = forms.CharField(label="Username", max_length=100)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
    name = forms.CharField(label="Name", max_length=100)
    role = forms.ChoiceField(label="Role", choices=CHOICES)


class RequesterCreationForm(forms.Form):
    username = forms.CharField(label="Username", max_length=100)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
    name = forms.CharField(label="Name", max_length=100)


class PatientLoginForm(forms.Form):
    username = forms.CharField(label="Username", max_length=100)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)


class PatientDataForm(forms.Form):
    name = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Enter name"}),
        label="Name",
        max_length=100,
    )
    accaddress = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Enter account address"}),
        label="Account Address",
        max_length=200,
    )
    gene = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Enter gene ID"}),
        label="Gene",
        max_length=100,
    )
    drugid = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Enter drug ID"}),
        label="Drug",
        max_length=100,
    )
    iscore = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Enter interaction score"}),
        label="Interaction Score",
        max_length=100,
    )
    annot = forms.CharField(
        widget=forms.TextInput(attrs={"placeholder": "Enter Annotation"}),
        label="Annotation",
    )
