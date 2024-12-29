#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static char selected_file[256] = "";
static char encryption_method[10] = "AES";

// выбор файла
void on_file_chosen(GtkWidget *widget, gpointer label) {
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(widget);
    gchar *filename = gtk_file_chooser_get_filename(chooser);
    strncpy(selected_file, filename, sizeof(selected_file));
    gtk_label_set_text(GTK_LABEL(label), filename);
    g_free(filename);
}

// выбор метода шифрования
void on_method_selected(GtkComboBoxText *combo, gpointer user_data) {
    const char *method = gtk_combo_box_text_get_active_text(combo);
    strncpy(encryption_method, method, sizeof(encryption_method));
}

// кнопка шифрования
void on_encrypt_button_clicked(GtkWidget *widget, gpointer key_entry) {
    if (strlen(selected_file) == 0) {
        g_print("Файл не выбран.\n");
        return;
    }

    g_print("Шифруем файл: %s\n", selected_file);
    g_print("Метод шифрования: %s\n", encryption_method);
    const gchar* txt = gtk_entry_get_text(key_entry);
    g_print("key: %s\n", txt);

    // file buffer
    FILE *buffer = fopen("buffer_temp.txt", "w");
    if (buffer == NULL) {
        g_print("Временный файл создан не был, операция приостановленна.");
        exit(1);
    }
    fputs(txt, buffer);
    fputs("\n", buffer);
    fputs(selected_file, buffer);
    fclose(buffer);
    system("./ecb_encr_128_exe");
}

// кнопка дешифрования
void on_decrypt_button_clicked(GtkWidget *widget, gpointer key_entry) {
    if (strlen(selected_file) == 0) {
        g_print("Файл не выбран.\n");
        return;
    }

    g_print("Дешифруем файл: %s\n", selected_file);
    g_print("Метод дешифрования: %s\n", encryption_method);

    const gchar* txt = gtk_entry_get_text(key_entry);
    g_print("key: %s\n", txt);
    // file buffer
    FILE *buffer = fopen("buffer_temp.txt", "w");
    if (buffer == NULL) {
        g_print("Временный файл создан не был, операция приостановленна.");
        exit(1);
    }
    fputs(txt, buffer);
    fputs("\n", buffer);
    fputs(selected_file, buffer);
    fclose(buffer);
    system("./ecb_decr_128_exe"); 
}

// создаем интерфейс
int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    // главное окно
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Шифрование данных");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // главное окно
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 15);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // поле для выбора файла
    GtkWidget *file_label = gtk_label_new("Выберите файл:");
    gtk_box_pack_start(GTK_BOX(vbox), file_label, FALSE, FALSE, 5);

    GtkWidget *file_chooser = gtk_file_chooser_button_new("Выберите файл", GTK_FILE_CHOOSER_ACTION_OPEN);
    g_signal_connect(file_chooser, "file-set", G_CALLBACK(on_file_chosen), file_label);
    gtk_box_pack_start(GTK_BOX(vbox), file_chooser, FALSE, FALSE, 5);

    // поле для выбора метода шифрования
    GtkWidget *method_label = gtk_label_new("Выберите метод шифрования:");
    gtk_box_pack_start(GTK_BOX(vbox), method_label, FALSE, FALSE, 5);

    GtkWidget *method_combo = gtk_combo_box_text_new();
    //gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(method_combo), NULL, "AES_128");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(method_combo), NULL, "AES (ECB) 128");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(method_combo), NULL, "AES (CBC)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(method_combo), NULL, "AES (CTR)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(method_combo), NULL, "ГОСТ");
    gtk_combo_box_set_active(GTK_COMBO_BOX(method_combo), 0);  // AES по умолчанию
    g_signal_connect(method_combo, "changed", G_CALLBACK(on_method_selected), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), method_combo, FALSE, FALSE, 5);

    // поле ввода ключа
    GtkWidget *key_label = gtk_label_new("Введите ключ (<=32 символа):");
    GtkWidget *key_entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), key_label, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), key_entry, FALSE, FALSE, 5);
    gtk_container_add(GTK_CONTAINER(window), key_entry);

    // кнопка для шифрования
    GtkWidget *encrypt_button = gtk_button_new_with_label("Зашифровать");
    g_signal_connect(encrypt_button, "clicked", G_CALLBACK(on_encrypt_button_clicked), key_entry);
    gtk_box_pack_start(GTK_BOX(vbox), encrypt_button, FALSE, FALSE, 10);

    // кнопка для дешифрования
    GtkWidget *decrypt_button = gtk_button_new_with_label("Дешифровать");
    g_signal_connect(decrypt_button, "clicked", G_CALLBACK(on_decrypt_button_clicked), key_entry);
    gtk_box_pack_start(GTK_BOX(vbox), decrypt_button, FALSE, FALSE, 10);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
