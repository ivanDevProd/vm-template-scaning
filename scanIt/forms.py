from django import forms
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class URLInputForm(forms.Form):
    urls = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter URLs separated by semicolons'}),
        label="Enter URLs",
        help_text="Separate multiple URLs using semicolons"
    )

    def clean_urls(self):
        data = self.cleaned_data['urls'].strip()
        
        # Check if the field is empty
        if not data:
            raise forms.ValidationError("This field cannot be empty.")

        # Split input by semicolon, stripping any surrounding whitespace
        urls = [url.strip() for url in data.split(';') if url.strip()]
        
        # If no valid URLs are found after splitting
        if not urls:
            raise forms.ValidationError("Please enter at least one valid URL.")

        validator = URLValidator()

        # Validate each URL
        for url in urls:
            try:
                validator(url)
            except ValidationError:
                raise forms.ValidationError(f"Invalid URL: {url}")

        return data

    
    
class FileUploadForm(forms.Form):
    file = forms.FileField(
        label='Select a file to upload',
        error_messages={
            'required': 'Please select a file to upload.'  # Custom error message
        }
    )
