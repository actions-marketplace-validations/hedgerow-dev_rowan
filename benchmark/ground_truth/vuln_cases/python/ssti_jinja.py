from jinja2 import Environment


def render(user_template):
    env = Environment()
    template = env.from_string(user_template)
    return template.render()
