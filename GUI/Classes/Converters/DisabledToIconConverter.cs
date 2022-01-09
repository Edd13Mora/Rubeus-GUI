using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;
using System.Windows.Media.Imaging;

namespace RubeusGui
{

    [ValueConversion(typeof(Boolean), typeof(BitmapFrame))]
    public class DisabledToIconConverter : IValueConverter
    {

        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value == null || (bool)value == false)
            {
                return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/male_user_16px.png"));
            }
            else
            {
                return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/lock_blue_16px.png"));
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }

    }
}
