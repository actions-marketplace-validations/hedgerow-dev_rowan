from crewai import Agent, Task, Crew
from crewai_tools import ScrapeWebsiteTool, CodeInterpreterTool

scraper = Agent(role="scraper", goal="fetch", backstory="", tools=[ScrapeWebsiteTool()])
writer = Agent(role="writer", goal="summarise", backstory="")
coder = Agent(role="coder", goal="run", backstory="", tools=[CodeInterpreterTool()])

t1 = Task(description="scrape the page", agent=scraper)
t2 = Task(description="summarise", agent=writer, context=[t1])
t3 = Task(description="execute", agent=coder, context=[t2])

crew = Crew(agents=[scraper, writer, coder], tasks=[t1, t2, t3])
