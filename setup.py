from setuptools import setup

setup(
    name='xss_unearth',
    version='1.0',
    description='Tool to analyze log files for XSS traces using a wordlist',
    package_data={'xss_unearth': ['xss-payload-list.txt']},
    install_requires=[  # Le dipendenze necessarie per "XSS Unearth"
        'argparse',
        'os',
        're',
        'urllib.parse',
        'datetime'
        # Aggiungi altre dipendenze se necessario
    ],
  
)



