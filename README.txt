Assistant Diagnostic Windows (Python)
=====================================
- Double-cliquez sur install.bat (clic droit > Exécuter en tant qu'administrateur recommandé).
- Le script installe Python si nécessaire, met à jour pip, installe les dépendances et lance l'application.
- Crée un raccourci sur le Bureau : "Assistant Diagnostic.lnk".
- Dépendances : customtkinter, psutil, screeninfo, pillow
- Optionnel (compilation .exe) : pyinstaller --onefile --noconsole --add-data "assets;assets" main.py
