/*  gui.hpp
 *
 *
 *  Copyright (C) 2020 Jfreegman <Jfreegman@gmail.com>
 *
 *  This file is part of SpicyPass.
 *
 *  SpicyPass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SpicyPass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SpicyPass.  If not, see <http://www.gnu.org/licenses/>.
 *
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

class GUI {
private:
    struct List_Store     ls;
    struct Callback_Data  cb_data;
    GtkApplication        *app;

    void init_window(GtkBuilder *builder);
    int load_new(Pass_Store &p, GtkBuilder *builder);
    int load(struct Callback_Data *cb_data);
public:
    void run(Pass_Store &p);
    GUI(void);
}; // class GUI

#endif // GUI_SUPPORT
#endif // GUI_H
