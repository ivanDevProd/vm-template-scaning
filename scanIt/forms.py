from django import forms
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class URLInputForm(forms.Form):
    urls = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter URLs separated by semicolons'})
    )

    def clean_urls(self):
        data = self.cleaned_data['urls']
    
        # Ensure data is a string
        if isinstance(data, str):
            urls = [url.strip() for url in data.split(';') if url.strip()]
        else:
            raise forms.ValidationError("The URLs input should be a string.")
        
        validator = URLValidator()

        for url in urls:
            try:
                validator(url)
            except ValidationError:
                raise forms.ValidationError(f"Invalid URL: {url}")

        return data
    
    
class FileUploadForm(forms.Form):
    file = forms.FileField(label='Select a file to upload')
