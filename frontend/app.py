import streamlit as st

# ASSIGNED TO: MJ

st.title("APP NAME")

# TODO: Import render_sidebar from components.sidebar
# TODO: Import render_map from components.map_view

# Logic:
# 1. Get user input from sidebar.
# 2. When user clicks "Search", send a POST request to http://localhost:8000/recommend.
# 3. Display the results using st.cards or a list.
# 4. Pass the results to render_map() to show them visually.