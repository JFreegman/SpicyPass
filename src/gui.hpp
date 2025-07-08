/*  gui.hpp
 *
 *  Copyright (C) 2020-2025 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass. SpicyPass is free software licensed
 *  under the GNU General Public License 3.0.
 */

#ifndef GUI_H
#define GUI_H

#ifdef GUI_SUPPORT

#include <gtk/gtk.h>

struct Callback_Data {
    GtkWidget         *window;
    GtkWidget         *widget1;
    GtkWidget         *widget2;
    GtkWidget         *widget3;
    GtkTextView       *widget4;
    GtkApplication    *app;

    Pass_Store        *p;
    struct List_Store *ls;

    bool              app_hidden;
};

struct List_Store {
    GtkListStore        *store;
    GtkTreeView         *view;
    GtkTreeViewColumn   *col1;
    GtkTreeViewColumn   *col2;
    GtkCellRenderer     *cr1;
};

class GUI
{
private:
    struct List_Store     ls;
    GtkApplication        *app;

    void init_window(GtkBuilder *builder, struct Callback_Data *cb_data);
    int load_new(Pass_Store &p, GtkBuilder *builder);
    int load(struct Callback_Data *cb_data);
public:
    void run(Pass_Store &p);
    GUI(void);
}; // class GUI

#endif // GUI_SUPPORT
#endif // GUI_H
