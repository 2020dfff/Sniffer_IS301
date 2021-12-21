from main_window import *

if __name__=='__main__':
    app = QApplication(sys.argv)
    window = main_window()
    sys.exit(app.exec_())
