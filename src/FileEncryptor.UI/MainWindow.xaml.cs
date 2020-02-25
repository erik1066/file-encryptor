using System;
using System.Collections.Generic;
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

        private void FilePathSelectButton_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            // Display OpenFileDialog by calling ShowDialog method 
            Nullable<bool> result = dlg.ShowDialog();

            // Get the selected file name and display in a TextBox 
            if (result == true)
            {
                // Open document 
                string filename = dlg.FileName;
                FilePath.Text = filename;
                Outcome.Text = string.Empty;
            }
        }

        private void OutputFilePathCopyButton_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(OutputFilePath.Text);
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            string inputFilePath = FilePath.Text;
            string outputFilePath = inputFilePath + ".enc";
            string password = Password.Text;
            string initVector = InitVector.Text;
            string salt = Salt.Text;

            try
            {
                Outcome.Text = string.Empty;
                FileCryptoOperations.EncryptFile(inputFilePath, outputFilePath, password, initVector, salt, 1_000_000);
                OutputFilePath.Text = outputFilePath;
                Outcome.Text = "Success!";
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(ex.Message);
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            string inputFilePath = FilePath.Text;
            string outputFilePath = inputFilePath + ".dec";
            string password = Password.Text;
            string initVector = InitVector.Text;
            string salt = Salt.Text;

            try
            {
                Outcome.Text = string.Empty;
                FileCryptoOperations.DecryptFile(inputFilePath, outputFilePath, password, initVector, salt, 1_000_000);
                OutputFilePath.Text = outputFilePath;
                Outcome.Text = "Success!";
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(ex.Message);
            }
        }

        private void PasswordGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var password = PasswordGenerator.Generate(24, 6);
            Password.Text = password;
        }

        private void InitVectorGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var iv = PasswordGenerator.Generate(16, 8);
            InitVector.Text = iv;
        }

        private void SaltGenerateButton_Click(object sender, RoutedEventArgs e)
        {
            var salt = PasswordGenerator.Generate(24, 6);
            Salt.Text = salt;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
