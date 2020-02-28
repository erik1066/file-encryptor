using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using FileEncryptor;

namespace FileEncryptor.UI
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            if (ViewModel.IsProcessing)
            {
                MessageBoxResult messageBoxResult = System.Windows.MessageBox.Show($"Closing the app will cancel the crypto operation. Proceed?", "Close Confirmation", System.Windows.MessageBoxButton.YesNo);
                if (messageBoxResult == MessageBoxResult.No)
                {
                    e.Cancel = true;
                    return;
                }
            }

            base.OnClosing(e);
        }

        private MainWindowViewModel ViewModel => ((this.DataContext) as MainWindowViewModel);

        private void InputFilePathSelectButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsProcessing) return;
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            dlg.CheckFileExists = true;

            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox 
            if (result == true)
            {
                // Open document 
                string filename = dlg.FileName;
                ViewModel.InputFilePath = filename;
                ViewModel.OutputFilePath = filename + ".brv";
                ViewModel.Outcome = string.Empty;
            }
        }

        private void OutputFilePathSelectButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsProcessing) return;
            Microsoft.Win32.SaveFileDialog dlg = new Microsoft.Win32.SaveFileDialog();
            dlg.CheckFileExists = false;
            dlg.CreatePrompt = true;

            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox 
            if (result == true)
            {
                // Open document 
                string filename = dlg.FileName;
                ViewModel.OutputFilePath = filename;
                ViewModel.Outcome = string.Empty;
            }
        }

        private void OutputFilePathCopyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(OutputFilePath.Text);
        }

        private void PasswordGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsProcessing) return;
            var password = PasswordGenerator.Generate(24, 6);
            ViewModel.Password = password;
        }

        private void InitVectorGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsProcessing) return;
            var iv = PasswordGenerator.Generate(16, 8);
            ViewModel.InitVector = iv;
        }

        private void SaltGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.IsProcessing) return;
            var salt = PasswordGenerator.Generate(24, 6);
            ViewModel.Salt = salt;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void PasswordCopyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(ViewModel.Password);
        }

        private void SaltCopyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(ViewModel.Salt);
        }

        private void InitVectorCopyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(ViewModel.InitVector);
        }
    }
}
