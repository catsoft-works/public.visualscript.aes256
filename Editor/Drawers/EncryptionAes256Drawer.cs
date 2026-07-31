using UnityEditor;
using UnityEditor.UIElements;
using UnityEngine.UIElements;
using VisualScript.Runtime.AES256;

namespace VisualScript.Editor.AES256
{
    [CustomPropertyDrawer(typeof(EncryptionAes256))]
    public class EncryptionAes256Drawer : PropertyDrawer
    {
        public override VisualElement CreatePropertyGUI(SerializedProperty property)
        {
            VisualElement content = new VisualElement();

            SerializedProperty secret = property.FindPropertyRelative("m_Secret");
            content.Add(new PropertyField(secret));

            SerializedProperty iterations = property.FindPropertyRelative("m_Iterations");
            content.Add(new PropertyField(iterations));

            return content;
        }
    }
}