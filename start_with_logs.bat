@echo off
echo Running LogSentinel diagnostic...
python diagnostic.py > diagnostic_output.txt 2>&1
echo Diagnostic complete. Check diagnostic_output.txt for results.

echo.
echo Attempting to start app...
python app.py > app_output.txt 2>&1 &
echo App started. Check app_output.txt for any errors.
echo Try opening http://127.0.0.1:5000 in your browser.
pause
